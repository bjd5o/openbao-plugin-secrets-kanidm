// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

// walRollback is called by OpenBao's rollback manager for WAL entries
// older than walRollbackMinAge, i.e. for issues or rotations that minted a
// token and then never finished.
func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data any) error {
	var w walAPIToken
	if err := mapstructure.Decode(data, &w); err != nil {
		return fmt.Errorf("decoding %s WAL entry: %w", kind, err)
	}
	if w.ServiceAccount == "" || w.Label == "" {
		// Nothing we can act on; let the entry be deleted.
		b.Logger().Warn("dropping malformed WAL entry", "kind", kind)
		return nil
	}

	b.rootLock.RLock()
	defer b.rootLock.RUnlock()

	client, cfg, err := b.getClient(ctx, req.Storage)
	if errors.Is(err, errNotConfigured) {
		// Without a token there is nothing we can do; keep the entry so
		// it is retried once the engine is configured again.
		return err
	}
	if err != nil {
		return err
	}

	switch kind {
	case walKindAPIToken:
		return b.rollbackAPIToken(ctx, client, req.Storage, &w)
	case walKindRootToken:
		return b.rollbackRootToken(ctx, client, cfg, &w)
	default:
		b.Logger().Warn("dropping WAL entry of unknown kind", "kind", kind)
		return nil
	}
}

// rollbackRootToken deletes a plugin token minted by an unfinished
// rotate-root, unless that token is the one now in config.
func (b *backend) rollbackRootToken(ctx context.Context, client *kanidm.Client, cfg *kanidmConfig, w *walAPIToken) error {
	tokens, err := client.ListAPITokens(ctx, w.ServiceAccount)
	if errors.Is(err, kanidm.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Label != w.Label || t.TokenID == cfg.TokenID {
			continue
		}
		if err := client.DeleteAPIToken(ctx, w.ServiceAccount, t.TokenID); err != nil && !errors.Is(err, kanidm.ErrNotFound) {
			return err
		}
		b.Logger().Info("rolled back unfinished root rotation", "token_id", t.TokenID)
	}
	return nil
}
