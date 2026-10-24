// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

const (
	configPath      = "config"
	labelPrefixPath = "label_prefix"

	defaultExpiryBuffer   = 5 * time.Minute
	defaultRequestTimeout = 30 * time.Second
)

var errNotConfigured = errors.New("the kanidm secrets engine is not configured; write a token to config/token first")

// kanidmConfig is stored at "config". The Kanidm URL lives at config/url,
// the CA bundle at config/ca, and the plugin token at config/token. None
// of those are written here.
type kanidmConfig struct {
	RequestTimeout time.Duration `json:"request_timeout"`
	ExpiryBuffer   time.Duration `json:"expiry_buffer"`
	RotationPeriod time.Duration `json:"rotation_period"`

	// LabelPrefix ("bao-<6 random>-") starts the label of every token this
	// mount mints, so tidy only ever touches this mount's tokens. It is
	// copied from the label_prefix storage entry, which outlives config
	// deletes.
	LabelPrefix string `json:"label_prefix"`

	// Learned from Kanidm when the token is set or rotated.
	AccountID     string    `json:"account_id"`
	AccountName   string    `json:"account_name"`
	TokenID       string    `json:"token_id"`
	TokenIssuedAt time.Time `json:"token_issued_at"`
}

func (c *kanidmConfig) rootLabelPrefix() string { return c.LabelPrefix + "root-" }

func (b *backend) newClient(ctx context.Context, s logical.Storage, cfg *kanidmConfig, token string) (*kanidm.Client, error) {
	origin, err := getKanidmURL(ctx, s)
	if err != nil {
		return nil, err
	}
	ca, err := getCACert(ctx, s)
	if err != nil {
		return nil, err
	}
	return kanidmClient(origin, ca, cfg, token)
}

func kanidmClient(origin, ca string, cfg *kanidmConfig, token string) (*kanidm.Client, error) {
	kc := kanidm.Config{URL: origin, Token: token, CACert: ca}
	if cfg != nil {
		kc.Timeout = cfg.RequestTimeout
	}
	return kanidm.New(kc)
}

func getConfig(ctx context.Context, s logical.Storage) (*kanidmConfig, error) {
	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var cfg kanidmConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}
	return &cfg, nil
}

func putConfig(ctx context.Context, s logical.Storage, cfg *kanidmConfig) error {
	entry, err := logical.StorageEntryJSON(configPath, cfg)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// getOrCreateLabelPrefix returns the mount's label prefix, generating and
// storing it on first use.
func getOrCreateLabelPrefix(ctx context.Context, s logical.Storage) (string, error) {
	entry, err := s.Get(ctx, labelPrefixPath)
	if err != nil {
		return "", err
	}
	if entry != nil && len(entry.Value) > 0 {
		return string(entry.Value), nil
	}
	r, err := randomString(6)
	if err != nil {
		return "", err
	}
	prefix := "bao-" + r + "-"
	if err := s.Put(ctx, &logical.StorageEntry{Key: labelPrefixPath, Value: []byte(prefix)}); err != nil {
		return "", err
	}
	return prefix, nil
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
		},
		Fields: map[string]*framework.FieldSchema{
			"request_timeout": {
				Type:        framework.TypeDurationSecond,
				Default:     int(defaultRequestTimeout.Seconds()),
				Description: "Timeout for each request to Kanidm.",
			},
			"expiry_buffer": {
				Type:        framework.TypeDurationSecond,
				Default:     int(defaultExpiryBuffer.Seconds()),
				Description: "Added to a role's max_ttl to set each token's Kanidm expiry, so normal revocation always runs first.",
			},
			"rotation_period": {
				Type:        framework.TypeDurationSecond,
				Default:     0,
				Description: "Rotate the plugin's own token automatically once it is older than this. 0 means manual rotation only.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		HelpSynopsis:    "Configure timeouts and rotation.",
		HelpDescription: "The Kanidm URL is read from config/url and the CA bundle from config/ca. The plugin token is written to config/token. Reads return that URL, plus everything stored here except the token. Delete also removes config/url, config/ca, and config/token.",
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	origin, err := getKanidmURL(ctx, req.Storage)
	if err != nil {
		origin = ""
	}
	data := map[string]any{
		"url":                  origin,
		"request_timeout":      int64(cfg.RequestTimeout.Seconds()),
		"expiry_buffer":        int64(cfg.ExpiryBuffer.Seconds()),
		"rotation_period":      int64(cfg.RotationPeriod.Seconds()),
		"label_prefix":         cfg.LabelPrefix,
		"service_account":      cfg.AccountName,
		"service_account_uuid": cfg.AccountID,
		"token_id":             cfg.TokenID,
		"token_issued_at":      "",
	}
	if !cfg.TokenIssuedAt.IsZero() {
		data["token_issued_at"] = cfg.TokenIssuedAt.UTC().Format(time.RFC3339)
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &kanidmConfig{
			RequestTimeout: defaultRequestTimeout,
			ExpiryBuffer:   defaultExpiryBuffer,
		}
	}

	if v, ok := d.GetOk("request_timeout"); ok {
		cfg.RequestTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("expiry_buffer"); ok {
		cfg.ExpiryBuffer = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("rotation_period"); ok {
		cfg.RotationPeriod = time.Duration(v.(int)) * time.Second
	}

	switch {
	case cfg.RequestTimeout <= 0:
		return logical.ErrorResponse("request_timeout must be greater than zero"), nil
	case cfg.ExpiryBuffer < 0:
		return logical.ErrorResponse("expiry_buffer must not be negative"), nil
	case cfg.RotationPeriod < 0:
		return logical.ErrorResponse("rotation_period must not be negative"), nil
	case cfg.RotationPeriod > 0 && cfg.RotationPeriod < 10*time.Minute:
		return logical.ErrorResponse("rotation_period must be 0 (manual) or at least 10m"), nil
	}

	prefix, err := getOrCreateLabelPrefix(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	cfg.LabelPrefix = prefix

	if err := putConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	for _, key := range []string{configPath, urlPath, caPath, tokenPath} {
		if err := req.Storage.Delete(ctx, key); err != nil {
			return nil, err
		}
	}
	b.resetClient()
	return nil, nil
}

// applyTokenIdentity checks token with Kanidm and records the account and
// token id on cfg. It returns warnings for a token whose id cannot be read.
func (b *backend) applyTokenIdentity(ctx context.Context, s logical.Storage, cfg *kanidmConfig, token string, tokenChanged bool) (*kanidm.Client, []string, error) {
	client, err := b.newClient(ctx, s, cfg, token)
	if err != nil {
		return nil, nil, err
	}
	self, err := client.Whoami(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("validating token with GET /v1/self: %s", err)
	}

	var warnings []string
	if tokenChanged {
		cfg.TokenID, cfg.TokenIssuedAt = "", b.now()
		claims, err := kanidm.ParseTokenClaims(token)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("could not read the token's id (%s); rotate-root will not be able to revoke this token, so revoke it in Kanidm by hand after rotating", err))
		case claims.AccountID != "" && claims.AccountID != self.UUID:
			return nil, nil, fmt.Errorf("token payload names account %s but Kanidm authenticated it as %s", claims.AccountID, self.UUID)
		case claims.Purpose != "" && claims.Purpose != "readwrite":
			return nil, nil, fmt.Errorf("token is %s; the plugin needs a read-write token to mint and revoke API tokens", claims.Purpose)
		default:
			cfg.TokenID = claims.TokenID
			if claims.IssuedAt > 0 {
				cfg.TokenIssuedAt = time.Unix(claims.IssuedAt, 0)
			}
		}
	} else if cfg.AccountID != "" && cfg.AccountID != self.UUID {
		return nil, nil, fmt.Errorf("token now authenticates as %s, not %s", self.UUID, cfg.AccountID)
	}
	cfg.AccountID, cfg.AccountName = self.UUID, self.Name
	return client, warnings, nil
}
