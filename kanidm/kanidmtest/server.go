// Package kanidmtest is an in-memory fake of the Kanidm endpoints the
// secrets engine uses, for unit tests.
package kanidmtest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Token is a token held by the fake.
type Token struct {
	AccountUUID string
	TokenID     string
	Label       string
	Expiry      *int64
	IssuedAt    int64
	ReadWrite   bool
	Secret      string
}

// Account is a service account held by the fake.
type Account struct {
	UUID string
	Name string
}

// Fault lets a test override a response. Returning handled=true stops
// normal processing; the fault may also just sleep and return false.
type Fault func(w http.ResponseWriter, r *http.Request) (handled bool)

// Server is the fake. All fields are guarded by mu.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	accounts map[string]*Account // by uuid
	tokens   map[string]*Token   // by token id
	secrets  map[string]string   // token string -> token id
	faults   []Fault
	calls    []string
	now      func() time.Time
}

// New starts a fake with no accounts. Close it when done.
func New() *Server {
	s := &Server{
		accounts: map[string]*Account{},
		tokens:   map[string]*Token{},
		secrets:  map[string]string{},
		now:      time.Now,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// AddAccount creates a service account and returns its UUID.
func (s *Server) AddAccount(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &Account{UUID: uuid(), Name: name}
	s.accounts[a.UUID] = a
	return a.UUID
}

// Mint creates a token directly (as an administrator would) and returns
// its secret and token id.
func (s *Server) Mint(account, label string, expiry *int64, readWrite bool) (secret, tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.findAccount(account)
	if a == nil {
		panic("kanidmtest: unknown account " + account)
	}
	t := s.mint(a, label, expiry, readWrite)
	return t.Secret, t.TokenID
}

// SetIssuedAt rewrites a token's issued_at, for tests that need old tokens.
func (s *Server) SetIssuedAt(tokenID string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenID].IssuedAt = t.Unix()
}

// Tokens returns copies of all tokens on an account (name or uuid).
func (s *Server) Tokens(account string) []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.findAccount(account)
	if a == nil {
		return nil
	}
	var out []Token
	for _, t := range s.tokens {
		if t.AccountUUID == a.UUID {
			out = append(out, *t)
		}
	}
	return out
}

// TokenByID returns a token, or nil.
func (s *Server) TokenByID(id string) *Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		c := *t
		return &c
	}
	return nil
}

// Valid reports whether a token string would authenticate.
func (s *Server) Valid(secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth(secret) != nil
}

// AddFault appends a fault hook consulted before every request.
func (s *Server) AddFault(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, f)
}

// ClearFaults removes all fault hooks.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = nil
}

// Calls returns "METHOD path" for every request received.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// FailOnce returns a fault that answers status for the first request
// matching method and path prefix.
func FailOnce(method, pathPrefix string, status int) Fault {
	var once sync.Once
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != method || !strings.HasPrefix(r.URL.Path, pathPrefix) {
			return false
		}
		hit := false
		once.Do(func() { hit = true })
		if hit {
			writeJSON(w, status, "injectedfault")
		}
		return hit
	}
}

// FailAlways answers status for every request matching method and path
// prefix.
func FailAlways(method, pathPrefix string, status int) Fault {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != method || !strings.HasPrefix(r.URL.Path, pathPrefix) {
			return false
		}
		writeJSON(w, status, "injectedfault")
		return true
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	faults := append([]Fault(nil), s.faults...)
	s.mu.Unlock()

	for _, f := range faults {
		if f(w, r) {
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	caller := s.auth(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if caller == nil {
		writeJSON(w, http.StatusUnauthorized, "notauthenticated")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/self":
		a := s.accounts[caller.AccountUUID]
		writeJSON(w, http.StatusOK, map[string]any{"youare": map[string]any{"attrs": map[string][]string{
			"uuid": {a.UUID}, "name": {a.Name}, "spn": {a.Name + "@localhost"},
		}}})

	case len(parts) >= 4 && parts[0] == "v1" && parts[1] == "service_account" && parts[3] == "_api_token":
		if !caller.ReadWrite && r.Method != http.MethodGet {
			writeJSON(w, http.StatusForbidden, "accessdenied")
			return
		}
		a := s.findAccount(parts[2])
		if a == nil {
			writeJSON(w, http.StatusNotFound, "nomatchingentries")
			return
		}
		switch {
		case r.Method == http.MethodPost && len(parts) == 4:
			var body struct {
				Label     string `json:"label"`
				Expiry    *int64 `json:"expiry"`
				ReadWrite bool   `json:"read_write"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			t := s.mint(a, body.Label, body.Expiry, body.ReadWrite)
			writeJSON(w, http.StatusOK, t.Secret)
		case r.Method == http.MethodGet && len(parts) == 4:
			list := []map[string]any{}
			for _, t := range s.tokens {
				if t.AccountUUID != a.UUID {
					continue
				}
				purpose := "readonly"
				if t.ReadWrite {
					purpose = "readwrite"
				}
				list = append(list, map[string]any{
					"account_id": t.AccountUUID, "token_id": t.TokenID, "label": t.Label,
					"expiry": t.Expiry, "issued_at": t.IssuedAt, "purpose": purpose,
				})
			}
			writeJSON(w, http.StatusOK, list)
		case r.Method == http.MethodDelete && len(parts) == 5:
			t, ok := s.tokens[parts[4]]
			if !ok || t.AccountUUID != a.UUID {
				writeJSON(w, http.StatusNotFound, "nomatchingentries")
				return
			}
			delete(s.tokens, t.TokenID)
			delete(s.secrets, t.Secret)
			writeJSON(w, http.StatusOK, nil)
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) auth(secret string) *Token {
	id, ok := s.secrets[secret]
	if !ok {
		return nil
	}
	t := s.tokens[id]
	if t.Expiry != nil && s.now().Unix() >= *t.Expiry {
		return nil
	}
	return t
}

func (s *Server) findAccount(ref string) *Account {
	if a, ok := s.accounts[ref]; ok {
		return a
	}
	for _, a := range s.accounts {
		if a.Name == ref || a.Name+"@localhost" == ref {
			return a
		}
	}
	return nil
}

func (s *Server) mint(a *Account, label string, expiry *int64, rw bool) *Token {
	t := &Token{
		AccountUUID: a.UUID, TokenID: uuid(), Label: label, Expiry: expiry,
		IssuedAt: s.now().Unix(), ReadWrite: rw,
	}
	purpose := "readonly"
	if rw {
		purpose = "readwrite"
	}
	payload, _ := json.Marshal(map[string]any{
		"account_id": t.AccountUUID, "token_id": t.TokenID, "label": label,
		"expiry": expiry, "issued_at": t.IssuedAt, "purpose": purpose,
	})
	t.Secret = "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig" + uuid()[:8]
	s.tokens[t.TokenID] = t
	s.secrets[t.Secret] = t.TokenID
	return t
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
