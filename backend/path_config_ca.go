// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// caPath is the mount-relative key that holds the PEM CA bundle. From
// outside the plugin the same entry is kanidm/config/ca.
const caPath = "config/ca"

// kanidmCAEntry is stored at caPath. An empty or missing entry means the
// plugin uses the system roots.
type kanidmCAEntry struct {
	CACert string `json:"ca_cert"`
}

func getCACert(ctx context.Context, s logical.Storage) (string, error) {
	entry, err := s.Get(ctx, caPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", caPath, err)
	}
	if entry == nil {
		return "", nil
	}
	var body kanidmCAEntry
	if err := entry.DecodeJSON(&body); err != nil {
		return "", fmt.Errorf("decoding %s: %w", caPath, err)
	}
	return body.CACert, nil
}

func putCACert(ctx context.Context, s logical.Storage, pem string) error {
	entry, err := logical.StorageEntryJSON(caPath, &kanidmCAEntry{CACert: pem})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func validateCACert(pem string) error {
	if pem == "" {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return errors.New("ca_cert contains no valid PEM certificates")
	}
	return nil
}

func pathConfigCA(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: caPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationSuffix: "ca",
		},
		Fields: map[string]*framework.FieldSchema{
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM CA bundle used to verify Kanidm's certificate instead of the system roots.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigCARead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigCAWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigCAWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigCADelete},
		},
		HelpSynopsis:    "Set the CA bundle used to verify Kanidm.",
		HelpDescription: "Writes store a PEM CA bundle. Reads return it. Delete to use the system roots again.",
	}
}

func (b *backend) pathConfigCARead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, caPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var body kanidmCAEntry
	if err := entry.DecodeJSON(&body); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"ca_cert": body.CACert}}, nil
}

func (b *backend) pathConfigCAWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	raw, ok := d.GetOk("ca_cert")
	if !ok {
		return logical.ErrorResponse("ca_cert is required"), nil
	}
	pem := raw.(string)
	if err := validateCACert(pem); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	prev, err := getCACert(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if pem == prev {
		return nil, nil
	}

	token, err := getRootToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if token != "" {
		cfg, err := getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		origin, err := getKanidmURL(ctx, req.Storage)
		if err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		client, err := kanidmClient(origin, pem, cfg, token)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		self, err := client.Whoami(ctx)
		if err != nil {
			return logical.ErrorResponse("validating token with GET /v1/self: %s", err), nil
		}
		if cfg != nil && (cfg.AccountID != self.UUID || cfg.AccountName != self.Name) {
			if cfg.AccountID != "" && cfg.AccountID != self.UUID {
				return logical.ErrorResponse("token now authenticates as %s, not %s", self.UUID, cfg.AccountID), nil
			}
			cfg.AccountID, cfg.AccountName = self.UUID, self.Name
			if err := putConfig(ctx, req.Storage, cfg); err != nil {
				return nil, err
			}
		}
	}

	if err := putCACert(ctx, req.Storage, pem); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}

func (b *backend) pathConfigCADelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()
	if err := req.Storage.Delete(ctx, caPath); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}
