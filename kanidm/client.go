// Package kanidm is a minimal client for the Kanidm REST endpoints the
// secrets engine needs: minting, listing and deleting service account API
// tokens, and checking the caller's own identity.
package kanidm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound is returned (wrapped in *APIError) when Kanidm answers 404.
var ErrNotFound = errors.New("kanidm: not found")

// ErrUnauthorized is returned (wrapped in *APIError) when Kanidm answers 401.
var ErrUnauthorized = errors.New("kanidm: not authenticated")

// APIError is a non-2xx response from Kanidm.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kanidm: %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func (e *APIError) Unwrap() error {
	switch e.Status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	}
	return nil
}

// Config holds what is needed to build a Client.
type Config struct {
	// URL is the Kanidm origin, e.g. https://idm.example.com.
	URL string
	// Token is the bearer token the client authenticates with.
	Token string
	// CACert is an optional PEM bundle used instead of the system roots.
	CACert string
	// Timeout bounds each request. Zero means 30 seconds.
	Timeout time.Duration
}

// Client talks to one Kanidm instance as one identity.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid url %q: scheme must be https or http", cfg.URL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid url %q: missing host", cfg.URL)
	}
	if cfg.Token == "" {
		return nil, errors.New("token is required")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("ca_cert contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &Client{
		base:  u,
		token: cfg.Token,
		http:  &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

// Self is the subset of GET /v1/self the engine uses.
type Self struct {
	UUID string
	Name string
	SPN  string
}

// APIToken is one entry of GET /v1/service_account/{id}/_api_token.
type APIToken struct {
	AccountID string `json:"account_id"`
	TokenID   string `json:"token_id"`
	Label     string `json:"label"`
	// Expiry and IssuedAt are Unix seconds. Expiry is nil for tokens that
	// never expire.
	Expiry   *int64 `json:"expiry"`
	IssuedAt int64  `json:"issued_at"`
	Purpose  string `json:"purpose"`
}

// IssuedAtTime returns IssuedAt as a time.Time.
func (t APIToken) IssuedAtTime() time.Time { return time.Unix(t.IssuedAt, 0) }

// Whoami calls GET /v1/self.
func (c *Client) Whoami(ctx context.Context) (*Self, error) {
	var resp struct {
		YouAre struct {
			Attrs map[string][]string `json:"attrs"`
		} `json:"youare"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/self", nil, &resp); err != nil {
		return nil, err
	}
	first := func(k string) string {
		if v := resp.YouAre.Attrs[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	s := &Self{UUID: first("uuid"), Name: first("name"), SPN: first("spn")}
	if s.UUID == "" {
		return nil, errors.New("kanidm: GET /v1/self returned no uuid")
	}
	return s, nil
}

// CreateAPIToken mints an API token for a service account (name, SPN or
// UUID) and returns the token string. A nil expiry means the token never
// expires.
func (c *Client) CreateAPIToken(ctx context.Context, account, label string, expiry *time.Time, readWrite bool) (string, error) {
	body := struct {
		Label     string `json:"label"`
		Expiry    *int64 `json:"expiry"`
		ReadWrite bool   `json:"read_write"`
	}{Label: label, ReadWrite: readWrite}
	if expiry != nil {
		e := expiry.Unix()
		body.Expiry = &e
	}
	var token string
	if err := c.do(ctx, http.MethodPost, tokensPath(account), body, &token); err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("kanidm: empty token in response")
	}
	return token, nil
}

// ListAPITokens returns all API tokens on a service account.
func (c *Client) ListAPITokens(ctx context.Context, account string) ([]APIToken, error) {
	var tokens []APIToken
	if err := c.do(ctx, http.MethodGet, tokensPath(account), nil, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// DeleteAPIToken deletes one API token. A token that does not exist yields
// an error matching ErrNotFound.
func (c *Client) DeleteAPIToken(ctx context.Context, account, tokenID string) error {
	return c.do(ctx, http.MethodDelete, tokensPath(account)+"/"+url.PathEscape(tokenID), nil, nil)
}

func tokensPath(account string) string {
	return "/v1/service_account/" + url.PathEscape(account) + "/_api_token"
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}

	// path is already escaped by the callers.
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kanidm: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("kanidm: %s %s: reading response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("kanidm: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

// TokenClaims is the unverified payload of a Kanidm API token in its
// default (JWS) form.
type TokenClaims struct {
	AccountID string `json:"account_id"`
	TokenID   string `json:"token_id"`
	Label     string `json:"label"`
	IssuedAt  int64  `json:"issued_at"`
	Purpose   string `json:"purpose"`
}

// ParseTokenClaims decodes the payload of a JWS-form API token without
// verifying it. It is used only to learn the plugin's own token_id so the
// token can be revoked later; it is never used for authorization.
func ParseTokenClaims(token string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not in JWS compact form")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding token payload: %w", err)
	}
	var c TokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("decoding token payload: %w", err)
	}
	if c.TokenID == "" {
		return nil, errors.New("token payload has no token_id")
	}
	return &c, nil
}
