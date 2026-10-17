//go:build integration

// Package integration runs the engine against real Kanidm and OpenBao
// containers. Run it through scripts/integration.sh, which builds the
// stack, bootstraps it and sets the ITEST_* variables.
//
// Kanidm accepts a deleted API token until five minutes after the token
// was issued (AUTH_TOKEN_GRACE_WINDOW). The tests therefore check two
// things for each revocation: that the token is gone from Kanidm at once,
// and that it gets 401 once the grace window has passed.
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const graceWindow = 5 * time.Minute

var env struct {
	state, compose, baoAddr, rootToken, kanidmAddr, kanidmName, observer, unsealKey string
	kanidmHTTP                                                                      *http.Client
}

func TestMain(m *testing.M) {
	env.state = os.Getenv("ITEST_STATE")
	if env.state == "" {
		fmt.Println("ITEST_STATE not set; run scripts/integration.sh")
		os.Exit(0)
	}
	env.compose = os.Getenv("ITEST_COMPOSE")
	env.baoAddr = os.Getenv("ITEST_BAO_ADDR")
	env.kanidmAddr = os.Getenv("ITEST_KANIDM_ADDR")
	env.kanidmName = os.Getenv("ITEST_KANIDM_NAME")
	env.rootToken = readState("root.token")
	env.unsealKey = readState("unseal.key")
	env.observer = readState("observer.token")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(readState("ca.pem")))
	env.kanidmHTTP = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: env.kanidmName},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, env.kanidmAddr)
			},
		},
	}
	os.Exit(m.Run())
}

func readState(name string) string {
	b, err := os.ReadFile(filepath.Join(env.state, name))
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b))
}

// --- OpenBao -------------------------------------------------------------

type baoResp struct {
	Status        int
	LeaseID       string         `json:"lease_id"`
	LeaseDuration int            `json:"lease_duration"`
	Renewable     bool           `json:"renewable"`
	Data          map[string]any `json:"data"`
	Errors        []string       `json:"errors"`
	Warnings      []string       `json:"warnings"`
}

func bao(t *testing.T, method, path string, body any) *baoResp {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, env.baoAddr+"/v1/"+path, r)
	req.Header.Set("X-Vault-Token", env.rootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out := &baoResp{Status: resp.StatusCode}
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		_ = json.Unmarshal(data, out)
	}
	return out
}

func baoOK(t *testing.T, method, path string, body any) *baoResp {
	t.Helper()
	r := bao(t, method, path, body)
	if r.Status >= 300 {
		t.Fatalf("%s %s: HTTP %d %v", method, path, r.Status, r.Errors)
	}
	return r
}

type issued struct {
	Token, TokenID, LeaseID string
	At                      time.Time
	Lease                   *baoResp
}

func issue(t *testing.T, role string) issued {
	t.Helper()
	at := time.Now()
	r := baoOK(t, http.MethodGet, "kanidm/api-token/"+role, nil)
	return issued{
		Token:   r.Data["token"].(string),
		TokenID: r.Data["token_id"].(string),
		LeaseID: r.LeaseID,
		At:      at,
		Lease:   r,
	}
}

func labelPrefix(t *testing.T) string {
	return baoOK(t, http.MethodGet, "kanidm/config", nil).Data["label_prefix"].(string)
}

// --- Kanidm --------------------------------------------------------------

func kanidm(t *testing.T, token, method, path string, body any, out any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://"+env.kanidmName+path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.kanidmHTTP.Do(req)
	if err != nil {
		t.Fatalf("kanidm %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("kanidm %s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func selfStatus(t *testing.T, token string) int {
	return kanidm(t, token, http.MethodGet, "/v1/self", nil, nil)
}

type apiToken struct {
	TokenID  string `json:"token_id"`
	Label    string `json:"label"`
	IssuedAt int64  `json:"issued_at"`
}

func tokensOn(t *testing.T, account string) map[string]apiToken {
	t.Helper()
	var list []apiToken
	if s := kanidm(t, env.observer, http.MethodGet, "/v1/service_account/"+account+"/_api_token", nil, &list); s != 200 {
		t.Fatalf("listing tokens on %s: HTTP %d", account, s)
	}
	out := map[string]apiToken{}
	for _, tok := range list {
		out[tok.TokenID] = tok
	}
	return out
}

func observerMint(t *testing.T, account, label string) (secret, id string) {
	t.Helper()
	if s := kanidm(t, env.observer, http.MethodPost, "/v1/service_account/"+account+"/_api_token",
		map[string]any{"label": label, "expiry": nil, "read_write": true}, &secret); s != 200 {
		t.Fatalf("observer mint on %s: HTTP %d", account, s)
	}
	for _, tok := range tokensOn(t, account) {
		if tok.Label == label {
			return secret, tok.TokenID
		}
	}
	t.Fatalf("observer mint on %s: token not listed", account)
	return "", ""
}

// --- waiting -------------------------------------------------------------

func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(3 * time.Second)
	}
}

// requireDead checks the token is gone from Kanidm now and gets 401 once
// Kanidm's grace window for its issue time has passed.
func requireDead(t *testing.T, account string, tok issued) {
	t.Helper()
	if _, ok := tokensOn(t, account)[tok.TokenID]; ok {
		t.Fatalf("token %s still listed in Kanidm", tok.TokenID)
	}
	wait := time.Until(tok.At.Add(graceWindow + 30*time.Second))
	eventually(t, wait+time.Minute, "token to get 401", func() bool {
		return selfStatus(t, tok.Token) == http.StatusUnauthorized
	})
}

// --- tests ---------------------------------------------------------------

func TestIntegration(t *testing.T) {
	roles := map[string]map[string]any{
		"itest":                  {"service_account": "tofu", "read_write": true, "max_ttl": "30m"},
		"short":                  {"service_account": "tofu", "max_ttl": "60s"},
		"renew":                  {"service_account": "tofu", "renewable": true, "ttl": "20s", "max_ttl": "60s"},
		"fault-crash-after-mint": {"service_account": "tofu", "max_ttl": "30m"},
	}
	for name, r := range roles {
		baoOK(t, http.MethodPost, "kanidm/roles/"+name, r)
	}

	t.Run("bootstrap", func(t *testing.T) {
		cfg := baoOK(t, http.MethodGet, "kanidm/config", nil).Data
		if _, ok := cfg["token"]; ok {
			t.Fatal("config read returned the token")
		}
		if cfg["service_account"] != "openbao-kanidm" || cfg["token_id"] == "" {
			t.Fatalf("unexpected config %v", cfg)
		}
		// The bootstrap token was rotated away: the only token left on
		// the plugin's account is the one in config.
		toks := tokensOn(t, "openbao-kanidm")
		if len(toks) != 1 {
			t.Fatalf("plugin account has %d tokens, want 1", len(toks))
		}
		if _, ok := toks[cfg["token_id"].(string)]; !ok {
			t.Fatal("the plugin's token is not the one in config")
		}
		for _, role := range []string{"tofu", "mailer"} {
			r := baoOK(t, http.MethodGet, "kanidm/roles/"+role, nil).Data
			if r["renewable"] != false || r["read_write"] != true {
				t.Fatalf("role %s: %v", role, r)
			}
		}
	})

	// Runs before the parallel tests, since it restarts OpenBao.
	t.Run("restart keeps leases revocable", func(t *testing.T) {
		tok := issue(t, "itest")
		restartOpenBao(t)
		baoOK(t, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": tok.LeaseID})
		if _, ok := tokensOn(t, "tofu")[tok.TokenID]; ok {
			t.Fatal("token survived revoke after restart")
		}
	})

	// Also sequential: the fault hook kills the whole plugin process, which
	// would fail any request in flight.
	t.Run("WAL rollback after a crash between mint and response", func(t *testing.T) {
		prefix := labelPrefix(t) + "fault-crash-after-mint-"
		if r := bao(t, http.MethodGet, "kanidm/api-token/fault-crash-after-mint", nil); r.Status < 400 {
			t.Fatalf("faulted read succeeded: %d", r.Status)
		}
		stray := func() int {
			n := 0
			for _, tok := range tokensOn(t, "tofu") {
				if strings.HasPrefix(tok.Label, prefix) {
					n++
				}
			}
			return n
		}
		// OpenBao restarts a crashed plugin and retries the request once,
		// so the hook fires twice; each attempt leaves its own WAL entry.
		if n := stray(); n < 1 {
			t.Fatal("no stray token right after the crash")
		}
		// WALRollbackMinAge is 1m and the rollback manager ticks each
		// minute.
		eventually(t, 4*time.Minute, "WAL rollback to delete the stray tokens", func() bool { return stray() == 0 })
		// The plugin came back and still issues tokens.
		tok := issue(t, "itest")
		baoOK(t, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": tok.LeaseID})
	})

	t.Run("parallel", func(t *testing.T) {
		t.Run("token works and revoke kills it", func(t *testing.T) {
			t.Parallel()
			tok := issue(t, "itest")
			if s := selfStatus(t, tok.Token); s != 200 {
				t.Fatalf("issued token: /v1/self HTTP %d", s)
			}
			if tok.Lease.Renewable || tok.Lease.LeaseDuration != 1800 {
				t.Fatalf("lease renewable=%v duration=%d", tok.Lease.Renewable, tok.Lease.LeaseDuration)
			}
			baoOK(t, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": tok.LeaseID})
			requireDead(t, "tofu", tok)
		})

		t.Run("lease expiry kills the token", func(t *testing.T) {
			t.Parallel()
			tok := issue(t, "short")
			if tok.Lease.LeaseDuration != 60 {
				t.Fatalf("lease duration %d, want 60", tok.Lease.LeaseDuration)
			}
			eventually(t, 2*time.Minute, "expired lease's token to leave Kanidm", func() bool {
				_, ok := tokensOn(t, "tofu")[tok.TokenID]
				return !ok
			})
			requireDead(t, "tofu", tok)
		})

		t.Run("renewable lease renews until max_ttl", func(t *testing.T) {
			t.Parallel()
			tok := issue(t, "renew")
			if !tok.Lease.Renewable || tok.Lease.LeaseDuration != 20 {
				t.Fatalf("lease renewable=%v duration=%d", tok.Lease.Renewable, tok.Lease.LeaseDuration)
			}
			renew := func() *baoResp {
				return bao(t, http.MethodPut, "sys/leases/renew", map[string]any{"lease_id": tok.LeaseID, "increment": 20})
			}
			time.Sleep(10 * time.Second)
			if r := renew(); r.Status != 200 || r.LeaseDuration > 20 || r.LeaseDuration < 15 {
				t.Fatalf("first renew: HTTP %d duration %d %v", r.Status, r.LeaseDuration, r.Errors)
			}
			time.Sleep(10 * time.Second)
			if r := renew(); r.Status != 200 {
				t.Fatalf("second renew: HTTP %d %v", r.Status, r.Errors)
			}
			// 45s in: only what is left of max_ttl.
			time.Sleep(25 * time.Second)
			if r := renew(); r.Status == 200 && r.LeaseDuration > 16 {
				t.Fatalf("renew near max_ttl gave %ds", r.LeaseDuration)
			}
			eventually(t, 90*time.Second, "token to leave Kanidm at max_ttl", func() bool {
				_, ok := tokensOn(t, "tofu")[tok.TokenID]
				return !ok
			})
			if r := renew(); r.Status == 200 {
				t.Fatal("renew past max_ttl succeeded")
			}
			requireDead(t, "tofu", tok)
		})

		t.Run("rotate-root revokes the old plugin token", func(t *testing.T) {
			t.Parallel()
			// Give the plugin a token whose secret the test knows.
			secret, id := observerMint(t, "openbao-kanidm", "itest-rotate")
			minted := time.Now()
			baoOK(t, http.MethodPost, "kanidm/config", map[string]any{"token": secret})
			if got := baoOK(t, http.MethodGet, "kanidm/config", nil).Data["token_id"]; got != id {
				t.Fatalf("config token_id %v, want %s", got, id)
			}
			r := baoOK(t, http.MethodPost, "kanidm/config/rotate-root", nil)
			if len(r.Warnings) > 0 {
				t.Fatalf("rotate-root warnings: %v", r.Warnings)
			}
			// Token reads still work with the new token.
			fresh := issue(t, "itest")
			if s := selfStatus(t, fresh.Token); s != 200 {
				t.Fatalf("token issued after rotation: HTTP %d", s)
			}
			baoOK(t, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": fresh.LeaseID})
			requireDead(t, "openbao-kanidm", issued{Token: secret, TokenID: id, At: minted})
		})

		t.Run("tidy removes this mount's strays only", func(t *testing.T) {
			t.Parallel()
			prefix := labelPrefix(t)
			_, stray := observerMint(t, "tofu", prefix+"tofu-byhand")
			_, other := observerMint(t, "tofu", "bao-zzzzzz-tofu-othermount")
			_, plain := observerMint(t, "tofu", "laptop")
			leased := issue(t, "itest")

			// Tidy spares tokens young enough to be mid-issue (6 minutes).
			baoOK(t, http.MethodPost, "kanidm/tidy", nil)
			if _, ok := tokensOn(t, "tofu")[stray]; !ok {
				t.Fatal("tidy removed a young token")
			}
			time.Sleep(6*time.Minute + 10*time.Second)
			r := baoOK(t, http.MethodPost, "kanidm/tidy", nil)
			toks := tokensOn(t, "tofu")
			if _, ok := toks[stray]; ok {
				t.Fatalf("stray prefixed token survived tidy (%v)", r.Data)
			}
			for name, id := range map[string]string{"other mount's": other, "unprefixed": plain, "leased": leased.TokenID} {
				if _, ok := toks[id]; !ok {
					t.Fatalf("tidy removed the %s token", name)
				}
			}
			baoOK(t, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": leased.LeaseID})
		})
	})
}

func restartOpenBao(t *testing.T) {
	t.Helper()
	cmd := exec.Command("docker", "compose", "-f", env.compose, "restart", "openbao")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("restarting openbao: %v", err)
	}
	eventually(t, time.Minute, "openbao to come back", func() bool {
		resp, err := http.Get(env.baoAddr + "/v1/sys/seal-status")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	baoOK(t, http.MethodPut, "sys/unseal", map[string]any{"key": env.unsealKey})
	eventually(t, time.Minute, "openbao to become active", func() bool {
		return bao(t, http.MethodGet, "sys/health", nil).Status == 200
	})
}
