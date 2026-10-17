package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

var errTidyRunning = errors.New("tidy is already running")

type tidyStats struct {
	ExpiredRecords int
	RevokedTokens  int
}

func pathTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationVerb:   "tidy",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTidyWrite},
		},
		HelpSynopsis:    "Clean up stray tokens and expired records now.",
		HelpDescription: "Revokes tokens carrying this mount's label prefix that have no lease record, and drops records past their expiry. The periodic function runs the same cleanup hourly.",
	}
}

func (b *backend) pathTidyWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	stats, err := b.tidy(ctx, req.Storage)
	switch {
	case errors.Is(err, errNotConfigured), errors.Is(err, errTidyRunning):
		return logical.ErrorResponse(err.Error()), nil
	case err != nil && stats == nil:
		return nil, err
	}
	resp := &logical.Response{Data: map[string]any{
		"expired_records": stats.ExpiredRecords,
		"revoked_tokens":  stats.RevokedTokens,
	}}
	if err != nil {
		resp.AddWarning(err.Error())
	}
	return resp, nil
}

// tidy revokes this mount's tokens that have no tokens/ record and drops
// records whose expiry has passed. Tokens without the mount's prefix, the
// plugin's current token, and tokens young enough to still be mid-issue
// are never touched; older root tokens left by rotations are revoked. Errors on one account do not stop the others; they are
// returned together with the stats.
func (b *backend) tidy(ctx context.Context, s logical.Storage) (*tidyStats, error) {
	if !b.tidyRunning.CompareAndSwap(false, true) {
		return nil, errTidyRunning
	}
	defer b.tidyRunning.Store(false)

	b.rootLock.RLock()
	defer b.rootLock.RUnlock()

	client, cfg, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg.LabelPrefix == "" {
		return nil, errors.New("config has no label prefix; rewrite config")
	}

	now := b.now()
	stats := &tidyStats{}
	var merr *multierror.Error

	ids, err := s.List(ctx, tokenRecordPrefix)
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(ids))
	accounts := map[string]bool{}
	for _, id := range ids {
		entry, err := s.Get(ctx, tokenRecordPrefix+id)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		var rec tokenRecord
		if err := entry.DecodeJSON(&rec); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("decoding record %s: %w", id, err))
			live[id] = true // unreadable: leave its token alone
			continue
		}
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			if err := s.Delete(ctx, tokenRecordPrefix+id); err != nil {
				return nil, err
			}
			stats.ExpiredRecords++
		} else {
			live[id] = true
		}
		if rec.ServiceAccount != "" {
			accounts[rec.ServiceAccount] = true
		}
	}

	roles, err := listRoles(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, name := range roles {
		r, err := getRole(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if r != nil {
			accounts[r.ServiceAccount] = true
		}
	}

	// The plugin's own account may hold old root tokens whose revocation
	// failed during rotate-root.
	if cfg.AccountID != "" {
		accounts[cfg.AccountID] = true
	}

	// An account can appear by name and by UUID; token ids dedupe that.
	seen := map[string]bool{}
	for account := range accounts {
		tokens, err := client.ListAPITokens(ctx, account)
		if errors.Is(err, kanidm.ErrNotFound) {
			continue
		}
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		for _, t := range tokens {
			if seen[t.TokenID] {
				continue
			}
			seen[t.TokenID] = true
			// Root tokens other than the current one are leftovers of
			// rotations, and are revoked like any other stray.
			switch {
			case !strings.HasPrefix(t.Label, cfg.LabelPrefix),
				t.TokenID == cfg.TokenID,
				cfg.TokenID == "" && strings.HasPrefix(t.Label, cfg.rootLabelPrefix()),
				live[t.TokenID],
				now.Sub(t.IssuedAtTime()) < tidyMinTokenAge:
				continue
			}
			if err := client.DeleteAPIToken(ctx, account, t.TokenID); err != nil && !errors.Is(err, kanidm.ErrNotFound) {
				merr = multierror.Append(merr, err)
				continue
			}
			stats.RevokedTokens++
			b.Logger().Info("tidy revoked stray token", "service_account", account, "token_id", t.TokenID, "label", t.Label)
		}
	}

	b.lastTidyMu.Lock()
	b.lastTidy = now
	b.lastTidyMu.Unlock()

	return stats, merr.ErrorOrNil()
}

// periodic runs from OpenBao's rollback manager (about once a minute). It
// tidies at most once per tidyInterval and rotates the plugin's token when
// rotation_period says it is due.
func (b *backend) periodic(ctx context.Context, req *logical.Request) error {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return err
	}

	var merr *multierror.Error
	if cfg.RotationPeriod > 0 && b.now().Sub(cfg.TokenIssuedAt) >= cfg.RotationPeriod {
		warnings, err := b.rotateRoot(ctx, req.Storage)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("automatic rotate-root: %w", err))
		}
		for _, w := range warnings {
			b.Logger().Warn("automatic rotate-root", "warning", w)
		}
	}

	b.lastTidyMu.Lock()
	due := b.now().Sub(b.lastTidy) >= b.tidyInterval
	b.lastTidyMu.Unlock()
	if due {
		stats, err := b.tidy(ctx, req.Storage)
		if err != nil && !errors.Is(err, errTidyRunning) {
			merr = multierror.Append(merr, fmt.Errorf("tidy: %w", err))
		}
		if stats != nil && (stats.ExpiredRecords > 0 || stats.RevokedTokens > 0) {
			b.Logger().Info("tidy finished", "expired_records", stats.ExpiredRecords, "revoked_tokens", stats.RevokedTokens)
		}
	}
	return merr.ErrorOrNil()
}
