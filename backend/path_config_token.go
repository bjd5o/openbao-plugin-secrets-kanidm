// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

const tokenPath = "config/token"

// rootToken is the seal-wrapped secret at config/token. The entry holds
// the plugin's Kanidm API token and nothing else.
type rootToken struct {
	Token string `json:"token"`
}

func getRootToken(ctx context.Context, s logical.Storage) (string, error) {
	entry, err := s.Get(ctx, tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading config/token: %w", err)
	}
	if entry == nil {
		return "", nil
	}
	var secret rootToken
	if err := entry.DecodeJSON(&secret); err != nil {
		return "", fmt.Errorf("decoding config/token: %w", err)
	}
	return secret.Token, nil
}

func putRootToken(ctx context.Context, s logical.Storage, token string) error {
	entry, err := logical.StorageEntryJSON(tokenPath, &rootToken{Token: token})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func pathConfigToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: tokenPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationSuffix: "token",
		},
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:         framework.TypeString,
				Description:  "Read-write API token for the plugin's own service account. Write-only.",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigTokenRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigTokenWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigTokenDelete},
		},
		HelpSynopsis:    "Set the plugin's Kanidm API token.",
		HelpDescription: "The token is stored on its own, seal-wrapped, at this path. Writes check it with GET /v1/self before saving. Reads return the token id and issue time, never the token.",
	}
}

func (b *backend) pathConfigTokenRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	token, err := getRootToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	data := map[string]any{
		"token_id":        "",
		"token_issued_at": "",
	}
	if cfg != nil {
		data["token_id"] = cfg.TokenID
		if !cfg.TokenIssuedAt.IsZero() {
			data["token_issued_at"] = cfg.TokenIssuedAt.UTC().Format(time.RFC3339)
		}
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathConfigTokenWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	raw, ok := d.GetOk("token")
	if !ok {
		return logical.ErrorResponse("token is required"), nil
	}
	token := strings.TrimSpace(raw.(string))
	if token == "" {
		return logical.ErrorResponse("token is required"), nil
	}

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

	prevToken, err := getRootToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	tokenChanged := token != prevToken
	prevAccount, prevTokenID := cfg.AccountID, cfg.TokenID

	client, warnings, err := b.applyTokenIdentity(ctx, req.Storage, cfg, token, tokenChanged)
	if err != nil {
		return logical.ErrorResponse("%s", err), nil
	}

	prefix, err := getOrCreateLabelPrefix(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	cfg.LabelPrefix = prefix

	if err := putRootToken(ctx, req.Storage, token); err != nil {
		return nil, err
	}
	if err := putConfig(ctx, req.Storage, cfg); err != nil {
		if prevToken != "" {
			if rbErr := putRootToken(ctx, req.Storage, prevToken); rbErr != nil {
				b.Logger().Error("restoring the previous token failed", "error", rbErr)
			}
		} else if delErr := req.Storage.Delete(ctx, tokenPath); delErr != nil {
			b.Logger().Error("removing the unsaved token failed", "error", delErr)
		}
		return nil, err
	}
	b.resetClient()

	// A replaced token is no longer used by this mount, so delete it
	// (with the new token) rather than leave it alive in Kanidm.
	if tokenChanged && prevToken != "" && prevTokenID != "" && prevTokenID != cfg.TokenID && prevAccount == cfg.AccountID {
		err := client.DeleteAPIToken(ctx, cfg.AccountID, prevTokenID)
		if err != nil && !errors.Is(err, kanidm.ErrNotFound) {
			warnings = append(warnings, fmt.Sprintf("the new token is saved, but deleting the previous token %s failed: %s; tidy will retry", prevTokenID, err))
		}
	}

	if len(warnings) == 0 {
		return nil, nil
	}
	return &logical.Response{Warnings: warnings}, nil
}

func (b *backend) pathConfigTokenDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	if err := req.Storage.Delete(ctx, tokenPath); err != nil {
		return nil, err
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		cfg.TokenID = ""
		cfg.TokenIssuedAt = time.Time{}
		if err := putConfig(ctx, req.Storage, cfg); err != nil {
			return nil, err
		}
	}
	b.resetClient()
	return nil, nil
}
