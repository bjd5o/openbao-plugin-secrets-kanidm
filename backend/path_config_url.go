// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// urlPath is the mount-relative key that holds the Kanidm origin. From
// outside the plugin the same entry is kanidm/config/url.
const urlPath = "config/url"

// kanidmURLEntry is stored at urlPath.
type kanidmURLEntry struct {
	URL string `json:"url"`
}

func getKanidmURL(ctx context.Context, s logical.Storage) (string, error) {
	entry, err := s.Get(ctx, urlPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", urlPath, err)
	}
	if entry == nil {
		return "", fmt.Errorf("kanidm url is not set; write it to %s", urlPath)
	}
	var body kanidmURLEntry
	if err := entry.DecodeJSON(&body); err != nil {
		return "", fmt.Errorf("decoding %s: %w", urlPath, err)
	}
	return normalizeKanidmURL(body.URL)
}

func putKanidmURL(ctx context.Context, s logical.Storage, origin string) error {
	entry, err := logical.StorageEntryJSON(urlPath, &kanidmURLEntry{URL: origin})
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func pathConfigURL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: urlPath,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kanidm",
			OperationSuffix: "url",
		},
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "Kanidm origin, for example https://idm.example.com.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigURLRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigURLWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigURLWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigURLDelete},
		},
		HelpSynopsis:    "Set the Kanidm origin.",
		HelpDescription: "Writes store the Kanidm origin. Reads return it.",
	}
}

func (b *backend) pathConfigURLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, urlPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var body kanidmURLEntry
	if err := entry.DecodeJSON(&body); err != nil {
		return nil, err
	}
	origin, err := normalizeKanidmURL(body.URL)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"url": origin}}, nil
}

func (b *backend) pathConfigURLWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()

	raw, ok := d.GetOk("url")
	if !ok {
		return logical.ErrorResponse("url is required"), nil
	}
	origin, err := normalizeKanidmURL(raw.(string))
	if err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if err := putKanidmURL(ctx, req.Storage, origin); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}

func (b *backend) pathConfigURLDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.rootLock.Lock()
	defer b.rootLock.Unlock()
	if err := req.Storage.Delete(ctx, urlPath); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}
