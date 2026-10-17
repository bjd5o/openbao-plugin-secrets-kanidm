package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm/kanidmtest"
)

type testEnv struct {
	t       *testing.T
	b       *backend
	storage logical.Storage
	kanidm  *kanidmtest.Server
	// rootSecret is the bootstrap token written to config.
	rootSecret string
	rootID     string
	pluginUUID string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	sys := logical.TestSystemView()
	sys.DefaultLeaseTTLVal = time.Hour
	sys.MaxLeaseTTLVal = 24 * time.Hour
	conf.System = sys

	b := newBackend()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	srv := kanidmtest.New()
	t.Cleanup(srv.Close)

	env := &testEnv{t: t, b: b, storage: conf.StorageView, kanidm: srv}
	env.pluginUUID = srv.AddAccount("openbao-kanidm")
	srv.AddAccount("tofu")
	srv.AddAccount("mailer")
	env.rootSecret, env.rootID = srv.Mint("openbao-kanidm", "bootstrap", nil, true)
	return env
}

func (e *testEnv) req(op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	e.t.Helper()
	return e.b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   e.storage,
	})
}

// ok runs a request and fails the test on any error.
func (e *testEnv) ok(op logical.Operation, path string, data map[string]any) *logical.Response {
	e.t.Helper()
	resp, err := e.req(op, path, data)
	if err != nil {
		e.t.Fatalf("%s %s: %v", op, path, err)
	}
	if resp != nil && resp.IsError() {
		e.t.Fatalf("%s %s: %v", op, path, resp.Error())
	}
	return resp
}

// fails runs a request and fails the test unless it errors; it returns
// the error text.
func (e *testEnv) fails(op logical.Operation, path string, data map[string]any) string {
	e.t.Helper()
	resp, err := e.req(op, path, data)
	if err != nil {
		return err.Error()
	}
	if resp != nil && resp.IsError() {
		return resp.Error().Error()
	}
	e.t.Fatalf("%s %s: expected an error, got %#v", op, path, resp)
	return ""
}

func (e *testEnv) configure(extra map[string]any) {
	e.t.Helper()
	data := map[string]any{"url": e.kanidm.URL, "token": e.rootSecret}
	for k, v := range extra {
		data[k] = v
	}
	e.ok(logical.UpdateOperation, "config", data)
}

func (e *testEnv) config() *kanidmConfig {
	e.t.Helper()
	cfg, err := getConfig(context.Background(), e.storage)
	if err != nil || cfg == nil {
		e.t.Fatalf("getConfig: %v %v", cfg, err)
	}
	return cfg
}

// issue reads api-token/<role> and returns the response.
func (e *testEnv) issue(role string) *logical.Response {
	e.t.Helper()
	resp := e.ok(logical.ReadOperation, "api-token/"+role, nil)
	if resp == nil || resp.Secret == nil {
		e.t.Fatalf("api-token/%s: no secret in %#v", role, resp)
	}
	return resp
}

// leaseRequest builds a revoke or renew request as OpenBao core would,
// round-tripping the internal data through JSON like lease storage does.
func (e *testEnv) leaseRequest(op logical.Operation, resp *logical.Response, issued time.Time, increment time.Duration) *logical.Request {
	e.t.Helper()
	raw, err := json.Marshal(resp.Secret.InternalData)
	if err != nil {
		e.t.Fatal(err)
	}
	var internal map[string]any
	if err := json.Unmarshal(raw, &internal); err != nil {
		e.t.Fatal(err)
	}
	secret := *resp.Secret
	secret.InternalData = internal
	secret.IssueTime = issued
	secret.Increment = increment
	return &logical.Request{Operation: op, Secret: &secret, Storage: e.storage}
}

func (e *testEnv) walCount() int {
	e.t.Helper()
	keys, err := framework.ListWAL(context.Background(), e.storage)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(keys)
}

func (e *testEnv) rollbackNow() {
	e.t.Helper()
	_, err := e.b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RollbackOperation,
		Data:      map[string]any{"immediate": true},
		Storage:   e.storage,
	})
	if err != nil {
		e.t.Fatalf("rollback: %v", err)
	}
}

func (e *testEnv) prefixedTokens(account string) []kanidmtest.Token {
	var out []kanidmtest.Token
	for _, t := range e.kanidm.Tokens(account) {
		if strings.HasPrefix(t.Label, e.config().LabelPrefix) {
			out = append(out, t)
		}
	}
	return out
}

func containsAll(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("%q does not contain %q", got, w)
		}
	}
}

// --- config ---------------------------------------------------------------

func TestConfigWriteValidatesAndHidesToken(t *testing.T) {
	e := newTestEnv(t)

	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"token": e.rootSecret}), "url is required")
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": e.kanidm.URL}), "token is required")
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": e.kanidm.URL, "token": "bogus"}), "/v1/self", "401")
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": "ftp://x", "token": e.rootSecret}), "scheme")
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": e.kanidm.URL, "token": e.rootSecret, "ca_cert": "nope"}), "PEM")
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": e.kanidm.URL, "token": e.rootSecret, "rotation_period": "5m"}), "rotation_period")
	ro, _ := e.kanidm.Mint("openbao-kanidm", "ro", nil, false)
	containsAll(t, e.fails(logical.UpdateOperation, "config", map[string]any{"url": e.kanidm.URL, "token": ro}), "read-write")

	e.configure(map[string]any{"rotation_period": "24h"})

	resp := e.ok(logical.ReadOperation, "config", nil)
	if _, ok := resp.Data["token"]; ok {
		t.Fatal("config read returned the token")
	}
	for _, v := range resp.Data {
		if s, ok := v.(string); ok && strings.Contains(s, e.rootSecret) {
			t.Fatal("config read leaked the token")
		}
	}
	if resp.Data["url"] != e.kanidm.URL || resp.Data["expiry_buffer"] != int64(300) ||
		resp.Data["rotation_period"] != int64(86400) || resp.Data["service_account"] != "openbao-kanidm" ||
		resp.Data["token_id"] != e.rootID {
		t.Fatalf("unexpected config: %#v", resp.Data)
	}
	prefix := resp.Data["label_prefix"].(string)
	if !strings.HasPrefix(prefix, "bao-") || len(prefix) != len("bao-xxxxxx-") || !strings.HasSuffix(prefix, "-") {
		t.Fatalf("bad label prefix %q", prefix)
	}

	// Updates keep the token and the prefix; the prefix even survives a
	// config delete.
	e.ok(logical.UpdateOperation, "config", map[string]any{"expiry_buffer": "10m"})
	cfg := e.config()
	if cfg.Token != e.rootSecret || cfg.ExpiryBuffer != 10*time.Minute || cfg.LabelPrefix != prefix {
		t.Fatalf("update lost fields: %+v", cfg)
	}
	e.ok(logical.DeleteOperation, "config", nil)
	if resp := e.ok(logical.ReadOperation, "config", nil); resp != nil {
		t.Fatalf("config still readable after delete: %#v", resp)
	}
	e.configure(nil)
	if e.config().LabelPrefix != prefix {
		t.Fatal("label prefix changed across config delete")
	}
}

// --- roles ----------------------------------------------------------------

func TestRoleRules(t *testing.T) {
	e := newTestEnv(t)

	containsAll(t, e.fails(logical.CreateOperation, "roles/x", map[string]any{"ttl": "1h"}), "service_account is required")
	containsAll(t, e.fails(logical.CreateOperation, "roles/x", map[string]any{
		"service_account": "tofu", "renewable": true, "ttl": "2h", "max_ttl": "1h",
	}), "must not be greater than max_ttl")
	containsAll(t, e.fails(logical.CreateOperation, "roles/x", map[string]any{
		"service_account": "tofu", "ttl": "2h", "max_ttl": "1h",
	}), "must not be greater than max_ttl")

	// Non-renewable: ttl is forced to max_ttl.
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "ttl": "10m", "max_ttl": "30m", "read_write": true})
	resp := e.ok(logical.ReadOperation, "roles/tofu", nil)
	if resp.Data["ttl"] != int64(1800) || resp.Data["max_ttl"] != int64(1800) || resp.Data["renewable"] != false || resp.Data["read_write"] != true {
		t.Fatalf("unexpected role: %#v", resp.Data)
	}
	// Non-renewable with only ttl: max_ttl follows.
	e.ok(logical.CreateOperation, "roles/mailer", map[string]any{"service_account": "mailer", "ttl": "12h"})
	resp = e.ok(logical.ReadOperation, "roles/mailer", nil)
	if resp.Data["ttl"] != int64(43200) || resp.Data["max_ttl"] != int64(43200) {
		t.Fatalf("unexpected role: %#v", resp.Data)
	}
	// Renewable keeps both.
	e.ok(logical.CreateOperation, "roles/renew", map[string]any{"service_account": "tofu", "renewable": true, "ttl": "10m", "max_ttl": "1h"})
	resp = e.ok(logical.ReadOperation, "roles/renew", nil)
	if resp.Data["ttl"] != int64(600) || resp.Data["max_ttl"] != int64(3600) || resp.Data["read_write"] != false {
		t.Fatalf("unexpected role: %#v", resp.Data)
	}
	// Updates are partial.
	e.ok(logical.UpdateOperation, "roles/renew", map[string]any{"ttl": "20m"})
	resp = e.ok(logical.ReadOperation, "roles/renew", nil)
	if resp.Data["ttl"] != int64(1200) || resp.Data["max_ttl"] != int64(3600) || resp.Data["service_account"] != "tofu" {
		t.Fatalf("unexpected role: %#v", resp.Data)
	}
	containsAll(t, e.fails(logical.UpdateOperation, "roles/renew", map[string]any{"ttl": "2h"}), "max_ttl")

	resp = e.ok(logical.ListOperation, "roles/", nil)
	if got := strings.Join(resp.Data["keys"].([]string), ","); got != "mailer,renew,tofu" {
		t.Fatalf("list = %s", got)
	}
	e.ok(logical.DeleteOperation, "roles/renew", nil)
	if resp := e.ok(logical.ReadOperation, "roles/renew", nil); resp != nil {
		t.Fatal("role still readable after delete")
	}
}

// --- issue, revoke, renew -------------------------------------------------

func TestIssueHappyPath(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m", "read_write": true})

	before := time.Now()
	resp := e.issue("tofu")

	token := resp.Data["token"].(string)
	tokenID := resp.Data["token_id"].(string)
	if !e.kanidm.Valid(token) {
		t.Fatal("issued token does not authenticate")
	}
	kt := e.kanidm.TokenByID(tokenID)
	if kt == nil || !kt.ReadWrite || !strings.HasPrefix(kt.Label, e.config().LabelPrefix+"tofu-") {
		t.Fatalf("unexpected kanidm token %+v", kt)
	}
	// Kanidm expiry = issue + max_ttl + buffer.
	wantExpiry := before.Add(30*time.Minute + 5*time.Minute).Unix()
	if kt.Expiry == nil || *kt.Expiry < wantExpiry-2 || *kt.Expiry > wantExpiry+2 {
		t.Fatalf("expiry %v, want about %d", kt.Expiry, wantExpiry)
	}
	if resp.Data["expires_at"] != time.Unix(*kt.Expiry, 0).UTC().Format(time.RFC3339) || resp.Data["service_account"] != "tofu" {
		t.Fatalf("unexpected response data %#v", resp.Data)
	}
	if resp.Secret.TTL != 30*time.Minute || resp.Secret.MaxTTL != 30*time.Minute || resp.Secret.Renewable {
		t.Fatalf("unexpected lease %+v", resp.Secret.LeaseOptions)
	}
	if entry, _ := e.storage.Get(context.Background(), tokenRecordPrefix+tokenID); entry == nil {
		t.Fatal("no tokens/ record")
	}
	if e.walCount() != 0 {
		t.Fatal("WAL entry left behind")
	}

	containsAll(t, e.fails(logical.ReadOperation, "api-token/nope", nil), "unknown role")

	// Revoke deletes it in Kanidm and removes the record.
	_, err := e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RevokeOperation, resp, time.Now(), 0))
	if err != nil {
		t.Fatal(err)
	}
	if e.kanidm.TokenByID(tokenID) != nil || e.kanidm.Valid(token) {
		t.Fatal("token survived revoke")
	}
	if entry, _ := e.storage.Get(context.Background(), tokenRecordPrefix+tokenID); entry != nil {
		t.Fatal("tokens/ record survived revoke")
	}
}

func TestIssueRequiresConfig(t *testing.T) {
	e := newTestEnv(t)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	containsAll(t, e.fails(logical.ReadOperation, "api-token/tofu", nil), "not configured")
}

func TestRevokeTreats404AsSuccess(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	resp := e.issue("tofu")
	tokenID := resp.Data["token_id"].(string)

	// Someone deleted the token in Kanidm already.
	e.kanidm.AddFault(kanidmtest.FailAlways(http.MethodDelete, "/v1/service_account/", http.StatusNotFound))
	if _, err := e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RevokeOperation, resp, time.Now(), 0)); err != nil {
		t.Fatalf("revoke with 404: %v", err)
	}
	if entry, _ := e.storage.Get(context.Background(), tokenRecordPrefix+tokenID); entry != nil {
		t.Fatal("record survived revoke")
	}

	// Any other failure is returned so OpenBao retries.
	e.kanidm.ClearFaults()
	resp = e.issue("tofu")
	e.kanidm.AddFault(kanidmtest.FailAlways(http.MethodDelete, "/v1/service_account/", http.StatusInternalServerError))
	if _, err := e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RevokeOperation, resp, time.Now(), 0)); err == nil {
		t.Fatal("revoke with 500 succeeded")
	}
	if entry, _ := e.storage.Get(context.Background(), tokenRecordPrefix+resp.Data["token_id"].(string)); entry == nil {
		t.Fatal("record dropped although revoke failed")
	}
}

func TestRenewCappedAtMaxTTL(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/r", map[string]any{"service_account": "tofu", "renewable": true, "ttl": "10m", "max_ttl": "30m"})
	resp := e.issue("r")
	if resp.Secret.TTL != 10*time.Minute || resp.Secret.MaxTTL != 30*time.Minute || !resp.Secret.Renewable {
		t.Fatalf("unexpected lease %+v", resp.Secret.LeaseOptions)
	}

	renew := func(issued time.Time) (*logical.Response, error) {
		return e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RenewOperation, resp, issued, 0))
	}

	// Early: a full ttl.
	r, err := renew(time.Now().Add(-5 * time.Minute))
	if err != nil || r.IsError() {
		t.Fatalf("renew: %v %v", r, err)
	}
	if r.Secret.TTL != 10*time.Minute {
		t.Fatalf("ttl %s, want 10m", r.Secret.TTL)
	}
	// Near the cap: what is left of max_ttl.
	r, err = renew(time.Now().Add(-25 * time.Minute))
	if err != nil || r.IsError() {
		t.Fatalf("renew: %v %v", r, err)
	}
	if r.Secret.TTL > 5*time.Minute+time.Second || r.Secret.TTL < 4*time.Minute {
		t.Fatalf("ttl %s, want about 5m", r.Secret.TTL)
	}
	// Past the cap: refused.
	r, err = renew(time.Now().Add(-31 * time.Minute))
	if err == nil && !r.IsError() {
		t.Fatalf("renew past max_ttl succeeded: %#v", r.Secret)
	}

	// Raising the role's max_ttl does not stretch an existing lease past
	// its token's Kanidm expiry.
	e.ok(logical.UpdateOperation, "roles/r", map[string]any{"max_ttl": "2h"})
	r, err = renew(time.Now().Add(-25 * time.Minute))
	if err != nil || r.IsError() || r.Secret.TTL > 5*time.Minute+time.Second {
		t.Fatalf("renew after max_ttl raise: %v %v", r, err)
	}
}

func TestNonRenewableRefusesRenew(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/r", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	resp := e.issue("r")
	if resp.Secret.Renewable {
		t.Fatal("lease is renewable")
	}
	r, err := e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RenewOperation, resp, time.Now(), 0))
	if err == nil && !r.IsError() {
		t.Fatal("renew of non-renewable lease succeeded")
	}

	// A renewable lease whose role was later made non-renewable stops
	// renewing too.
	e.ok(logical.UpdateOperation, "roles/r", map[string]any{"renewable": true, "ttl": "10m"})
	resp = e.issue("r")
	e.ok(logical.UpdateOperation, "roles/r", map[string]any{"renewable": false})
	r, err = e.b.HandleRequest(context.Background(), e.leaseRequest(logical.RenewOperation, resp, time.Now(), 0))
	if err == nil && !r.IsError() {
		t.Fatal("renew after role became non-renewable succeeded")
	}
}

// --- WAL rollback ---------------------------------------------------------

func TestFailureAfterMintIsCleanedUpInline(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})

	// Listing fails right after the POST, so the token id is unknown.
	e.kanidm.AddFault(kanidmtest.FailOnce(http.MethodGet, "/v1/service_account/tofu/_api_token", http.StatusInternalServerError))
	e.fails(logical.ReadOperation, "api-token/tofu", nil)

	if n := len(e.prefixedTokens("tofu")); n != 0 {
		t.Fatalf("%d tokens leaked", n)
	}
	if e.walCount() != 0 {
		t.Fatal("WAL entry left after successful inline cleanup")
	}
}

func TestWALRollbackAfterFailureFollowingPOST(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})

	// The request fails after the mint and Kanidm is too unwell for the
	// inline cleanup, so the token is left behind with its WAL entry.
	e.b.afterMint = func(string) error {
		e.kanidm.AddFault(kanidmtest.FailAlways(http.MethodGet, "/v1/service_account/", http.StatusServiceUnavailable))
		return errInjected
	}
	e.fails(logical.ReadOperation, "api-token/tofu", nil)
	e.b.afterMint = nil

	if n := len(e.prefixedTokens("tofu")); n != 1 {
		t.Fatalf("want the stray token present before rollback, have %d", n)
	}
	if e.walCount() != 1 {
		t.Fatal("no WAL entry for the stray token")
	}

	// A young entry is left alone by the normal (non-immediate) rollback.
	e.kanidm.ClearFaults()
	if _, err := e.b.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: e.storage}); err != nil {
		t.Fatal(err)
	}
	if e.walCount() != 1 {
		t.Fatal("WAL entry rolled back before WALRollbackMinAge")
	}

	e.rollbackNow()
	if n := len(e.prefixedTokens("tofu")); n != 0 {
		t.Fatalf("%d tokens survived rollback", n)
	}
	if e.walCount() != 0 {
		t.Fatal("WAL entry survived rollback")
	}
}

func TestWALRollbackAfterTimeoutOnPOST(t *testing.T) {
	e := newTestEnv(t)
	e.configure(map[string]any{"request_timeout": "1s"})
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})

	// Kanidm mints the token but the response never arrives.
	e.kanidm.AddFault(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}
		var body struct{ Label string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		e.kanidm.Mint("tofu", body.Label, nil, false)
		time.Sleep(1500 * time.Millisecond)
		return true
	})
	e.fails(logical.ReadOperation, "api-token/tofu", nil)
	e.kanidm.ClearFaults()

	if n := len(e.prefixedTokens("tofu")); n != 1 || e.walCount() != 1 {
		t.Fatalf("want 1 stray token and 1 WAL entry, have %d and %d", n, e.walCount())
	}
	e.rollbackNow()
	if n := len(e.prefixedTokens("tofu")); n != 0 || e.walCount() != 0 {
		t.Fatalf("after rollback: %d tokens, %d WAL entries", n, e.walCount())
	}
}

func TestMintRejectedLeavesNoWAL(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	e.kanidm.AddFault(kanidmtest.FailOnce(http.MethodPost, "/v1/service_account/tofu", http.StatusForbidden))
	containsAll(t, e.fails(logical.ReadOperation, "api-token/tofu", nil), "403")
	if e.walCount() != 0 {
		t.Fatal("WAL entry left for a rejected mint")
	}
}

// --- tidy -----------------------------------------------------------------

func TestTidyOnlyTouchesThisMountsPrefix(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "2h"})
	prefix := e.config().LabelPrefix

	leased := e.issue("tofu").Data["token_id"].(string)
	_, stray := e.kanidm.Mint("tofu", prefix+"tofu-byhand", nil, false)
	_, young := e.kanidm.Mint("tofu", prefix+"tofu-inflight", nil, false)
	_, foreign := e.kanidm.Mint("tofu", "bao-zzzzzz-tofu-othermount", nil, false)
	_, human := e.kanidm.Mint("tofu", "laptop", nil, false)
	old := time.Now().Add(-time.Hour)
	for _, id := range []string{leased, stray, foreign, human} {
		e.kanidm.SetIssuedAt(id, old)
	}

	resp := e.ok(logical.UpdateOperation, "tidy", nil)
	if resp.Data["revoked_tokens"] != 1 || resp.Data["expired_records"] != 0 {
		t.Fatalf("tidy stats %#v", resp.Data)
	}
	if e.kanidm.TokenByID(stray) != nil {
		t.Fatal("stray prefixed token survived tidy")
	}
	for name, id := range map[string]string{"leased": leased, "young": young, "foreign": foreign, "human": human} {
		if e.kanidm.TokenByID(id) == nil {
			t.Fatalf("tidy removed the %s token", name)
		}
	}
}

func TestTidyDropsExpiredRecordsAndSparesRootToken(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	// The plugin's own account is served by a role too, which must not
	// let tidy touch the plugin's token.
	e.ok(logical.CreateOperation, "roles/self", map[string]any{"service_account": "openbao-kanidm", "max_ttl": "30m"})
	e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	rootID := e.config().TokenID

	leased := e.issue("self").Data["token_id"].(string)

	// Jump past the token's expiry: the record goes, and the expired token
	// in Kanidm now has no record, so it is revoked too.
	e.b.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	resp := e.ok(logical.UpdateOperation, "tidy", nil)
	if resp.Data["expired_records"] != 1 || resp.Data["revoked_tokens"] != 1 {
		t.Fatalf("tidy stats %#v", resp.Data)
	}
	if e.kanidm.TokenByID(leased) != nil {
		t.Fatal("expired token survived tidy")
	}
	if e.kanidm.TokenByID(rootID) == nil {
		t.Fatal("tidy revoked the plugin's own token")
	}
}

func TestPeriodicTidyIsRateLimited(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	prefix := e.config().LabelPrefix
	periodic := func() {
		if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
			t.Fatal(err)
		}
	}

	periodic() // first run tidies
	_, stray := e.kanidm.Mint("tofu", prefix+"tofu-byhand", nil, false)
	e.kanidm.SetIssuedAt(stray, time.Now().Add(-time.Hour))
	periodic() // within the interval: no tidy
	if e.kanidm.TokenByID(stray) == nil {
		t.Fatal("periodic tidied within the interval")
	}
	e.b.lastTidy = time.Now().Add(-2 * time.Hour)
	periodic()
	if e.kanidm.TokenByID(stray) != nil {
		t.Fatal("periodic did not tidy after the interval")
	}
}

// --- rotate-root ----------------------------------------------------------

func TestRotateRoot(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})
	e.issue("tofu") // warm the client cache with the old token

	resp := e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	cfg := e.config()
	if cfg.Token == e.rootSecret || cfg.TokenID == e.rootID || resp.Data["token_id"] != cfg.TokenID {
		t.Fatal("token not rotated")
	}
	if !e.kanidm.Valid(cfg.Token) || e.kanidm.Valid(e.rootSecret) {
		t.Fatal("new token invalid or old token still valid")
	}
	if !strings.HasPrefix(e.kanidm.TokenByID(cfg.TokenID).Label, cfg.LabelPrefix+"root-") {
		t.Fatal("new root token has the wrong label")
	}
	if e.walCount() != 0 {
		t.Fatal("WAL entry left after rotation")
	}

	// Reads use the new token.
	e.issue("tofu")
	if strings.Contains(e.ok(logical.ReadOperation, "config", nil).Data["token_id"].(string), e.rootID) {
		t.Fatal("config still shows the old token id")
	}

	// And it rotates again.
	e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	if e.kanidm.Valid(cfg.Token) || e.config().TokenID == cfg.TokenID {
		t.Fatal("second rotation did not replace the token")
	}
}

func TestRotateRootSavesNewBeforeRevokingOld(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)

	// When the old token is revoked, the saved config must already hold
	// the new one.
	var sawNew bool
	e.kanidm.AddFault(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/"+e.rootID) {
			cfg, _ := getConfig(context.Background(), e.storage)
			sawNew = cfg != nil && cfg.TokenID != e.rootID && cfg.Token != e.rootSecret
		}
		return false
	})
	e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	if !sawNew {
		t.Fatal("old token was revoked before the new one was saved")
	}
}

func TestRotateRootKeepsNewTokenWhenRevokeFails(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.kanidm.AddFault(kanidmtest.FailAlways(http.MethodDelete, "/v1/service_account/", http.StatusInternalServerError))

	resp := e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], e.rootID) {
		t.Fatalf("want a warning naming the old token, got %v", resp.Warnings)
	}
	cfg := e.config()
	if cfg.Token == e.rootSecret || !e.kanidm.Valid(cfg.Token) {
		t.Fatal("new token not kept")
	}
}

func TestRotateRootFailureKeepsOldToken(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	// The new token's /v1/self check fails, so the new token is deleted
	// and config is untouched.
	var n int
	e.kanidm.AddFault(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/self" && r.Header.Get("Authorization") != "Bearer "+e.rootSecret {
			n++
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		return false
	})
	e.fails(logical.UpdateOperation, "config/rotate-root", nil)
	if n == 0 {
		t.Fatal("new token was never checked")
	}
	cfg := e.config()
	if cfg.Token != e.rootSecret || !e.kanidm.Valid(e.rootSecret) {
		t.Fatal("old token replaced or revoked by a failed rotation")
	}
	if toks := e.kanidm.Tokens("openbao-kanidm"); len(toks) != 1 {
		t.Fatalf("failed rotation left %d tokens on the plugin account", len(toks))
	}
	if e.walCount() != 0 {
		t.Fatal("WAL entry left after inline cleanup")
	}
}

func TestPeriodicRotatesWhenDue(t *testing.T) {
	e := newTestEnv(t)
	e.configure(map[string]any{"rotation_period": "1h"})
	run := func() {
		if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.storage}); err != nil {
			t.Fatal(err)
		}
	}
	run()
	if e.config().TokenID != e.rootID {
		t.Fatal("rotated before rotation_period")
	}
	e.b.now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	run()
	if e.config().TokenID == e.rootID || e.kanidm.Valid(e.rootSecret) {
		t.Fatal("did not rotate after rotation_period")
	}
}

func TestRotationWaitsForInFlightReads(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	e.ok(logical.CreateOperation, "roles/tofu", map[string]any{"service_account": "tofu", "max_ttl": "30m"})

	// Hold an issue in the middle of its Kanidm calls and start a
	// rotation; the rotation must not revoke the old token until the
	// issue is done with it.
	release := make(chan struct{})
	entered := make(chan struct{})
	e.b.afterMint = func(string) error {
		close(entered)
		<-release
		return nil
	}
	issueErr := make(chan error, 1)
	go func() {
		resp, err := e.req(logical.ReadOperation, "api-token/tofu", nil)
		if err == nil && resp.IsError() {
			err = resp.Error()
		}
		issueErr <- err
	}()
	<-entered

	rotated := make(chan struct{})
	go func() {
		e.ok(logical.UpdateOperation, "config/rotate-root", nil)
		close(rotated)
	}()
	select {
	case <-rotated:
		t.Fatal("rotation ran while a read held the old token")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-issueErr; err != nil {
		t.Fatalf("issue during rotation: %v", err)
	}
	<-rotated
	if e.kanidm.Valid(e.rootSecret) {
		t.Fatal("old token still valid after rotation")
	}
}

func TestRootRotationWALRollbackSparesCurrentToken(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	cfg := e.config()

	// Simulate a crash after minting a root token during rotation.
	label := cfg.rootLabelPrefix() + "crashed"
	if _, err := framework.PutWAL(context.Background(), e.storage, walKindRootToken, &walAPIToken{ServiceAccount: e.pluginUUID, Label: label}); err != nil {
		t.Fatal(err)
	}
	_, stray := e.kanidm.Mint("openbao-kanidm", label, nil, true)
	e.rollbackNow()
	if e.kanidm.TokenByID(stray) != nil {
		t.Fatal("stray root token survived rollback")
	}
	if !e.kanidm.Valid(e.rootSecret) {
		t.Fatal("rollback revoked the current root token")
	}
}

type injectedError struct{}

func (injectedError) Error() string { return "injected failure" }

var errInjected = injectedError{}

func TestConfigTokenChangeDeletesPreviousToken(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	next, nextID := e.kanidm.Mint("openbao-kanidm", "replacement", nil, true)

	resp := e.ok(logical.UpdateOperation, "config", map[string]any{"token": next})
	if resp != nil && len(resp.Warnings) > 0 {
		t.Fatalf("warnings: %v", resp.Warnings)
	}
	if e.config().TokenID != nextID {
		t.Fatal("config does not hold the new token")
	}
	if e.kanidm.TokenByID(e.rootID) != nil {
		t.Fatal("previous plugin token survived the config write")
	}
	// Re-writing the same token is a no-op.
	e.ok(logical.UpdateOperation, "config", map[string]any{"token": next})
	if !e.kanidm.Valid(next) {
		t.Fatal("re-writing the same token revoked it")
	}
}

func TestTidyRevokesStaleRootTokens(t *testing.T) {
	e := newTestEnv(t)
	e.configure(nil)
	// Rotation with a failing revoke leaves the old token behind.
	e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	first := e.config().TokenID
	e.kanidm.AddFault(kanidmtest.FailAlways(http.MethodDelete, "/v1/service_account/", http.StatusInternalServerError))
	e.ok(logical.UpdateOperation, "config/rotate-root", nil)
	e.kanidm.ClearFaults()
	current := e.config().TokenID
	if e.kanidm.TokenByID(first) == nil {
		t.Fatal("setup: old root token should still exist")
	}

	e.b.now = func() time.Time { return time.Now().Add(time.Hour) }
	e.ok(logical.UpdateOperation, "tidy", nil)
	if e.kanidm.TokenByID(first) != nil {
		t.Fatal("stale root token survived tidy")
	}
	if e.kanidm.TokenByID(current) == nil || !e.kanidm.Valid(e.config().Token) {
		t.Fatal("tidy revoked the current root token")
	}
}
