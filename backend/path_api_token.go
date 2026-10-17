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
	tokenRecordPrefix = "tokens/"
	walKindAPIToken   = "api_token"
)

// tokenRecord is stored at tokens/<token_id> for every token whose lease
// is live. Tidy revokes prefixed tokens that have no record.
type tokenRecord struct {
	ServiceAccount     string    `json:"service_account"` // account UUID
	ServiceAccountName string    `json:"service_account_name"`
	Label              string    `json:"label"`
	Role               string    `json:"role"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// walAPIToken is written before minting, so a token minted by a request
// that never completes is found and deleted by WAL rollback.
type walAPIToken struct {
	ServiceAccount string `json:"service_account" mapstructure:"service_account"`
	Label          string `json:"label" mapstructure:"label"`
}

func pathAPIToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "api-token/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationVerb:   "generate",
			OperationSuffix: "api-token",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathAPITokenRead},
		},
		HelpSynopsis:    "Mint a Kanidm API token for a role's service account.",
		HelpDescription: "Returns token, token_id, service_account and expires_at under a lease. The token is deleted in Kanidm when the lease ends.",
	}
}

func (b *backend) pathAPITokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	r, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("unknown role %q", name), nil
	}

	b.rootLock.RLock()
	defer b.rootLock.RUnlock()

	client, cfg, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, maxTTL := r.leaseTimes(b.System())
	if maxTTL <= 0 {
		return nil, errors.New("role and mount give no max TTL; set max_ttl on the role")
	}
	now := b.now()
	expiry := now.Add(maxTTL + cfg.ExpiryBuffer).Truncate(time.Second)

	suffix, err := randomString(16)
	if err != nil {
		return nil, err
	}
	label := cfg.LabelPrefix + name + "-" + suffix

	walID, err := framework.PutWAL(ctx, req.Storage, walKindAPIToken, &walAPIToken{
		ServiceAccount: r.ServiceAccount,
		Label:          label,
	})
	if err != nil {
		return nil, fmt.Errorf("writing WAL entry: %w", err)
	}

	token, err := client.CreateAPIToken(ctx, r.ServiceAccount, label, &expiry, r.ReadWrite)
	if err != nil {
		// Kanidm answered, so nothing was minted and the WAL can go. On a
		// transport error the token may exist, so rollback must check.
		var apiErr *kanidm.APIError
		if errors.As(err, &apiErr) {
			b.deleteWAL(ctx, req.Storage, walID)
		}
		return nil, fmt.Errorf("minting token for %q: %w", r.ServiceAccount, err)
	}

	// From here on a failure must not leak the token: clean up inline if
	// possible, and leave the WAL entry in place if not.
	fail := func(err error) (*logical.Response, error) {
		w := &walAPIToken{ServiceAccount: r.ServiceAccount, Label: label}
		if rbErr := b.rollbackAPIToken(ctx, client, req.Storage, w); rbErr != nil {
			b.Logger().Warn("inline cleanup failed; WAL rollback will retry", "label", label, "error", rbErr)
		} else {
			b.deleteWAL(ctx, req.Storage, walID)
		}
		return nil, err
	}

	if b.afterMint != nil {
		if err := b.afterMint(name); err != nil {
			return fail(err)
		}
	}

	info, err := findToken(ctx, client, r.ServiceAccount, label, token)
	if err != nil {
		return fail(err)
	}

	rec := &tokenRecord{
		ServiceAccount:     info.AccountID,
		ServiceAccountName: r.ServiceAccount,
		Label:              label,
		Role:               name,
		IssuedAt:           now,
		ExpiresAt:          expiry,
	}
	entry, err := logical.StorageEntryJSON(tokenRecordPrefix+info.TokenID, rec)
	if err != nil {
		return fail(err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fail(fmt.Errorf("recording token: %w", err))
	}

	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		// Returning the token now would let rollback delete a token in
		// use, so fail the request instead.
		return fail(fmt.Errorf("deleting WAL entry: %w", err))
	}

	resp := b.Secret(secretAPITokenType).Response(map[string]any{
		"token":           token,
		"token_id":        info.TokenID,
		"service_account": r.ServiceAccount,
		"expires_at":      expiry.UTC().Format(time.RFC3339),
	}, map[string]any{
		"service_account":      info.AccountID,
		"service_account_name": r.ServiceAccount,
		"token_id":             info.TokenID,
		"label":                label,
		"role":                 name,
		"max_ttl":              int64(maxTTL.Seconds()),
	})
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = r.Renewable
	return resp, nil
}

// findToken finds a just-minted token's entry by label. Kanidm does not
// enforce unique labels, so if several entries match, the token's own
// payload picks the right one.
func findToken(ctx context.Context, client *kanidm.Client, account, label, token string) (*kanidm.APIToken, error) {
	tokens, err := client.ListAPITokens(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("listing tokens for %q: %w", account, err)
	}
	var matches []kanidm.APIToken
	for _, t := range tokens {
		if t.Label == label {
			matches = append(matches, t)
		}
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	if claims, err := kanidm.ParseTokenClaims(token); err == nil {
		for _, t := range matches {
			if t.TokenID == claims.TokenID {
				return &t, nil
			}
		}
	}
	return nil, fmt.Errorf("found %d tokens labelled %q on %q, expected 1", len(matches), label, account)
}

// rollbackAPIToken deletes every token carrying the WAL entry's label, and
// their records. A missing account counts as done.
func (b *backend) rollbackAPIToken(ctx context.Context, client *kanidm.Client, s logical.Storage, w *walAPIToken) error {
	tokens, err := client.ListAPITokens(ctx, w.ServiceAccount)
	if errors.Is(err, kanidm.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Label != w.Label {
			continue
		}
		if err := client.DeleteAPIToken(ctx, w.ServiceAccount, t.TokenID); err != nil && !errors.Is(err, kanidm.ErrNotFound) {
			return err
		}
		if err := s.Delete(ctx, tokenRecordPrefix+t.TokenID); err != nil {
			return err
		}
		b.Logger().Info("rolled back token", "service_account", w.ServiceAccount, "token_id", t.TokenID, "label", t.Label)
	}
	return nil
}

func (b *backend) deleteWAL(ctx context.Context, s logical.Storage, id string) {
	if err := framework.DeleteWAL(ctx, s, id); err != nil {
		b.Logger().Warn("deleting WAL entry; rollback will clean it up", "id", id, "error", err)
	}
}
