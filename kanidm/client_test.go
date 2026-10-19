// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package kanidm_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"openbao-plugin-secrets-kanidm/kanidm"
	"openbao-plugin-secrets-kanidm/kanidm/kanidmtest"
)

func TestClientCalls(t *testing.T) {
	srv := kanidmtest.New()
	defer srv.Close()
	pluginUUID := srv.AddAccount("openbao-kanidm")
	srv.AddAccount("tofu")
	secret, _ := srv.Mint("openbao-kanidm", "bootstrap", nil, true)

	c, err := kanidm.New(kanidm.Config{URL: srv.URL + "/", Token: secret})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	self, err := c.Whoami(ctx)
	if err != nil || self.UUID != pluginUUID || self.Name != "openbao-kanidm" {
		t.Fatalf("whoami = %+v, %v", self, err)
	}

	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tok, err := c.CreateAPIToken(ctx, "tofu", "bao-abc", &exp, true)
	if err != nil || !srv.Valid(tok) {
		t.Fatalf("create = %q, %v", tok, err)
	}
	list, err := c.ListAPITokens(ctx, "tofu")
	if err != nil || len(list) != 1 || list[0].Label != "bao-abc" || list[0].Expiry == nil || *list[0].Expiry != exp.Unix() || list[0].Purpose != "readwrite" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	claims, err := kanidm.ParseTokenClaims(tok)
	if err != nil || claims.TokenID != list[0].TokenID {
		t.Fatalf("claims = %+v, %v", claims, err)
	}

	if err := c.DeleteAPIToken(ctx, "tofu", list[0].TokenID); err != nil {
		t.Fatal(err)
	}
	err = c.DeleteAPIToken(ctx, "tofu", list[0].TokenID)
	var apiErr *kanidm.APIError
	if !errors.Is(err, kanidm.ErrNotFound) || !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
	if _, err := c.ListAPITokens(ctx, "nope"); !errors.Is(err, kanidm.ErrNotFound) {
		t.Fatalf("list on missing account = %v, want ErrNotFound", err)
	}

	bad, _ := kanidm.New(kanidm.Config{URL: srv.URL, Token: "bogus"})
	if _, err := bad.Whoami(ctx); !errors.Is(err, kanidm.ErrUnauthorized) {
		t.Fatalf("whoami with bad token = %v, want ErrUnauthorized", err)
	}
}

func TestClientTimeout(t *testing.T) {
	srv := kanidmtest.New()
	defer srv.Close()
	srv.AddFault(func(w http.ResponseWriter, r *http.Request) bool {
		time.Sleep(300 * time.Millisecond)
		return false
	})
	c, _ := kanidm.New(kanidm.Config{URL: srv.URL, Token: "x", Timeout: 50 * time.Millisecond})
	if _, err := c.Whoami(context.Background()); err == nil {
		t.Fatal("expected a timeout")
	}
}

func TestNewValidates(t *testing.T) {
	for _, cfg := range []kanidm.Config{
		{URL: "", Token: "x"},
		{URL: "idm.example.com", Token: "x"},
		{URL: "https://idm.example.com", Token: ""},
		{URL: "https://idm.example.com", Token: "x", CACert: "not pem"},
	} {
		if _, err := kanidm.New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestParseTokenClaimsRejectsCompactTokens(t *testing.T) {
	if _, err := kanidm.ParseTokenClaims("short-opaque-token"); err == nil {
		t.Fatal("expected an error")
	}
}
