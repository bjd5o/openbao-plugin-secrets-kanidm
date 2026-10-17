package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

const secretAPITokenType = "kanidm_api_token"

// The lease's internal data is the only thing revocation needs, so keep
// these keys stable across plugin versions.
func secretAPIToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretAPITokenType,
		Fields: map[string]*framework.FieldSchema{
			"token":           {Type: framework.TypeString, Description: "Kanidm API token."},
			"token_id":        {Type: framework.TypeString, Description: "Kanidm token id."},
			"service_account": {Type: framework.TypeString, Description: "Service account the token belongs to."},
			"expires_at":      {Type: framework.TypeString, Description: "Kanidm expiry of the token (RFC 3339)."},
		},
		Revoke: b.secretAPITokenRevoke,
		Renew:  b.secretAPITokenRenew,
	}
}

func internalString(req *logical.Request, key string) (string, error) {
	v, ok := req.Secret.InternalData[key]
	if !ok {
		return "", fmt.Errorf("lease is missing internal field %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("lease internal field %q is not a string", key)
	}
	return s, nil
}

func internalSeconds(req *logical.Request, key string) time.Duration {
	switch v := req.Secret.InternalData[key].(type) {
	case int64:
		return time.Duration(v) * time.Second
	case int:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v) * time.Second
	case json.Number:
		n, _ := v.Int64()
		return time.Duration(n) * time.Second
	}
	return 0
}

func (b *backend) secretAPITokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	account, err := internalString(req, "service_account")
	if err != nil {
		return nil, err
	}
	tokenID, err := internalString(req, "token_id")
	if err != nil {
		return nil, err
	}

	b.rootLock.RLock()
	defer b.rootLock.RUnlock()

	client, _, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	err = client.DeleteAPIToken(ctx, account, tokenID)
	switch {
	case errors.Is(err, kanidm.ErrNotFound):
		b.Logger().Debug("token already gone", "service_account", account, "token_id", tokenID)
	case err != nil:
		return nil, fmt.Errorf("revoking token %s: %w", tokenID, err)
	}

	if err := req.Storage.Delete(ctx, tokenRecordPrefix+tokenID); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) secretAPITokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleName, err := internalString(req, "role")
	if err != nil {
		return nil, err
	}
	r, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("role %q no longer exists; read a new token instead", roleName), nil
	}
	if !r.Renewable {
		return logical.ErrorResponse("role %q is not renewable; read a new token instead", roleName), nil
	}

	ttl, maxTTL := r.leaseTimes(b.System())
	// The Kanidm token expires at issue + the max_ttl in force at issue,
	// so never renew past that even if the role now allows more.
	if issued := internalSeconds(req, "max_ttl"); issued > 0 && issued < maxTTL {
		maxTTL = issued
	}

	ttl, warnings, err := framework.CalculateTTL(b.System(), req.Secret.Increment, ttl, 0, maxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{Secret: req.Secret, Warnings: warnings}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	return resp, nil
}
