// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const rolePrefix = "roles/"

// role is stored at roles/<name>.
type role struct {
	ServiceAccount string        `json:"service_account"`
	ReadWrite      bool          `json:"read_write"`
	TTL            time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	Renewable      bool          `json:"renewable"`
}

// leaseTimes returns the lease TTL and max TTL for a token issued now,
// after applying the mount's limits. For non-renewable roles ttl equals
// maxTTL.
func (r *role) leaseTimes(sys logical.SystemView) (ttl, maxTTL time.Duration) {
	maxTTL = r.MaxTTL
	if sysMax := sys.MaxLeaseTTL(); maxTTL <= 0 || (sysMax > 0 && maxTTL > sysMax) {
		maxTTL = sysMax
	}
	ttl = r.TTL
	if ttl <= 0 {
		ttl = sys.DefaultLeaseTTL()
	}
	if !r.Renewable || ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL
}

func getRole(ctx context.Context, s logical.Storage, name string) (*role, error) {
	entry, err := s.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("reading role %q: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}
	var r role
	if err := entry.DecodeJSON(&r); err != nil {
		return nil, fmt.Errorf("decoding role %q: %w", name, err)
	}
	return &r, nil
}

func listRoles(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, rolePrefix)
}

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rolePrefix + "?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kanidm",
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
			HelpSynopsis: "List the configured roles.",
		},
		{
			Pattern: rolePrefix + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kanidm",
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"service_account": {
					Type:        framework.TypeString,
					Description: "Kanidm service account (name, SPN or UUID) whose tokens this role mints. Its entry_managed_by must include the plugin's account.",
				},
				"read_write": {
					Type:        framework.TypeBool,
					Default:     false,
					Description: "Mint read-write tokens instead of read-only ones.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lease length at issue and per renewal. Defaults to the mount's default lease TTL.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Hard cap on the lease, counted from issue. Defaults to the mount's max lease TTL.",
				},
				"renewable": {
					Type:        framework.TypeBool,
					Default:     false,
					Description: "Allow lease renewal up to max_ttl. When false, ttl is forced to max_ttl.",
				},
			},
			ExistenceCheck: b.pathRoleExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
			HelpSynopsis:    "Manage the roles tokens can be issued for.",
			HelpDescription: "A role names one Kanidm service account and the lifetime of the tokens minted for it.",
		},
	}
}

func (b *backend) pathRoleExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	r, err := getRole(ctx, req.Storage, d.Get("name").(string))
	return r != nil, err
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := listRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	r, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || r == nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"service_account": r.ServiceAccount,
		"read_write":      r.ReadWrite,
		"ttl":             int64(r.TTL.Seconds()),
		"max_ttl":         int64(r.MaxTTL.Seconds()),
		"renewable":       r.Renewable,
	}}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	r, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = &role{}
	}

	if v, ok := d.GetOk("service_account"); ok {
		r.ServiceAccount = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("read_write"); ok {
		r.ReadWrite = v.(bool)
	}
	if v, ok := d.GetOk("renewable"); ok {
		r.Renewable = v.(bool)
	}
	ttlSet, maxSet := false, false
	if v, ok := d.GetOk("ttl"); ok {
		r.TTL, ttlSet = time.Duration(v.(int))*time.Second, true
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		r.MaxTTL, maxSet = time.Duration(v.(int))*time.Second, true
	}

	if r.ServiceAccount == "" {
		return logical.ErrorResponse("service_account is required"), nil
	}
	if r.TTL < 0 || r.MaxTTL < 0 {
		return logical.ErrorResponse("ttl and max_ttl must not be negative"), nil
	}

	// For a non-renewable role, a ttl written on its own defines the lease.
	if !r.Renewable && ttlSet && !maxSet {
		r.MaxTTL = r.TTL
	}
	if r.MaxTTL > 0 && r.TTL > r.MaxTTL {
		return logical.ErrorResponse("ttl (%s) must not be greater than max_ttl (%s)", r.TTL, r.MaxTTL), nil
	}

	var warnings []string
	if !r.Renewable {
		// A non-renewable lease lives exactly max_ttl.
		if r.MaxTTL == 0 {
			r.MaxTTL = r.TTL
		} else if ttlSet && r.TTL != r.MaxTTL {
			warnings = append(warnings, fmt.Sprintf("role is not renewable, so ttl is set to max_ttl (%s)", r.MaxTTL))
		}
		r.TTL = r.MaxTTL
	}
	if sysMax := b.System().MaxLeaseTTL(); sysMax > 0 && r.MaxTTL > sysMax {
		warnings = append(warnings, fmt.Sprintf("max_ttl (%s) is greater than the mount's max lease TTL (%s); leases and tokens will be capped at the mount's value", r.MaxTTL, sysMax))
	}

	entry, err := logical.StorageEntryJSON(rolePrefix+name, r)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	if len(warnings) == 0 {
		return nil, nil
	}
	return &logical.Response{Warnings: warnings}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, rolePrefix+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}
