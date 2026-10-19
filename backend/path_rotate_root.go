// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

const walKindRootToken = "root_token"

func pathRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationVerb:   "rotate",
			OperationSuffix: "root-credentials",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRootWrite},
		},
		HelpSynopsis:    "Rotate the plugin's own Kanidm token.",
		HelpDescription: "Mints a new token for the plugin's account, checks it, saves it, then revokes the old token with the new one.",
	}
}

func (b *backend) pathRotateRootWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	warnings, err := b.rotateRoot(ctx, req.Storage)
	if errors.Is(err, errNotConfigured) {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err != nil {
		return nil, err
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data:     map[string]any{"token_id": cfg.TokenID},
		Warnings: warnings,
	}, nil
}

// rotateRoot replaces the plugin's own token. The new token is saved
// before the old one is revoked; if the revoke fails, the new token is kept
// and a warning returned.
func (b *backend) rotateRoot(ctx context.Context, s logical.Storage) ([]string, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errNotConfigured
	}
	oldClient, err := cfg.newClient(cfg.Token)
	if err != nil {
		return nil, err
	}

	account := cfg.AccountID
	if account == "" {
		self, err := oldClient.Whoami(ctx)
		if err != nil {
			return nil, fmt.Errorf("looking up the plugin's account: %w", err)
		}
		account = self.UUID
	}

	suffix, err := randomString(16)
	if err != nil {
		return nil, err
	}
	label := cfg.rootLabelPrefix() + suffix

	walID, err := framework.PutWAL(ctx, s, walKindRootToken, &walAPIToken{ServiceAccount: account, Label: label})
	if err != nil {
		return nil, err
	}

	newToken, err := oldClient.CreateAPIToken(ctx, account, label, nil, true)
	if err != nil {
		var apiErr *kanidm.APIError
		if errors.As(err, &apiErr) {
			b.deleteWAL(ctx, s, walID)
		}
		return nil, fmt.Errorf("minting the plugin's new token: %w", err)
	}

	fail := func(err error) ([]string, error) {
		if rbErr := b.rollbackRootToken(ctx, oldClient, cfg, &walAPIToken{ServiceAccount: account, Label: label}); rbErr != nil {
			b.Logger().Warn("inline cleanup of new root token failed; WAL rollback will retry", "error", rbErr)
		} else {
			b.deleteWAL(ctx, s, walID)
		}
		return nil, err
	}

	info, err := findToken(ctx, oldClient, account, label, newToken)
	if err != nil {
		return fail(err)
	}
	newClient, err := cfg.newClient(newToken)
	if err != nil {
		return fail(err)
	}
	self, err := newClient.Whoami(ctx)
	if err != nil {
		return fail(fmt.Errorf("checking the new token with GET /v1/self: %w", err))
	}
	if self.UUID != account {
		return fail(fmt.Errorf("new token authenticates as %s, expected %s", self.UUID, account))
	}

	oldTokenID := cfg.TokenID
	next := *cfg
	next.Token = newToken
	next.TokenID = info.TokenID
	next.TokenIssuedAt = info.IssuedAtTime()
	next.AccountID, next.AccountName = self.UUID, self.Name
	if err := putConfig(ctx, s, &next); err != nil {
		return fail(fmt.Errorf("saving the new token: %w", err))
	}
	// The new token is saved; the WAL entry would now only ever skip it.
	b.deleteWAL(ctx, s, walID)
	b.resetClient()
	b.Logger().Info("rotated the plugin's token", "token_id", info.TokenID)

	if oldTokenID == "" {
		return []string{"the old token's id is unknown, so it was not revoked; revoke it in Kanidm by hand"}, nil
	}
	if oldTokenID == info.TokenID {
		return nil, nil
	}
	if err := newClient.DeleteAPIToken(ctx, account, oldTokenID); err != nil && !errors.Is(err, kanidm.ErrNotFound) {
		b.Logger().Warn("revoking the old plugin token failed", "token_id", oldTokenID, "error", err)
		return []string{fmt.Sprintf("the new token is saved, but revoking the old token %s failed: %s; revoke it in Kanidm by hand", oldTokenID, err)}, nil
	}
	return nil, nil
}
