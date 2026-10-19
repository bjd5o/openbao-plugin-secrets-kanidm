// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

// Package backend implements the OpenBao Kanidm secrets engine: it mints
// Kanidm service account API tokens under OpenBao leases and revokes them
// when the lease ends.
package backend

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"openbao-plugin-secrets-kanidm/kanidm"
)

// Version is the plugin version reported to OpenBao. It is overridden at
// build time with -ldflags "-X .../backend.Version=v0.1.0".
var Version = "v0.0.0-dev"

const (
	// walRollbackMinAge must exceed the longest time an issue or rotation
	// takes from PutWAL to DeleteWAL.
	walRollbackMinAge = time.Minute

	// defaultTidyInterval rate-limits tidy runs from the periodic function.
	defaultTidyInterval = time.Hour

	// tidyMinTokenAge protects tokens that are in the middle of being
	// issued: a token younger than this is never revoked by tidy, because
	// the WAL entry covering it may not have been rolled back yet.
	tidyMinTokenAge = walRollbackMinAge + 5*time.Minute
)

// Factory returns a configured backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	// rootLock serialises use of the plugin's own Kanidm token against
	// changes to it. Anything that calls Kanidm holds it for reading;
	// config writes, config deletes and rotate-root hold it for writing,
	// so a rotation never races a request using the old token.
	rootLock sync.RWMutex

	// clientMu guards the cached client.
	clientMu sync.Mutex
	client   *kanidm.Client

	tidyRunning  atomic.Bool
	lastTidyMu   sync.Mutex
	lastTidy     time.Time
	tidyInterval time.Duration

	// now is the clock; tests replace it.
	now func() time.Time

	// afterMint, when set, runs after the Kanidm token is minted and before
	// the lease is recorded. Tests use it to inject failures.
	afterMint func(role string) error
}

func newBackend() *backend {
	b := &backend{
		now:          time.Now,
		tidyInterval: defaultTidyInterval,
	}
	b.afterMint = faultHook

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathRotateRoot(b),
				pathTidy(b),
			},
			pathRoles(b),
			[]*framework.Path{pathAPIToken(b)},
		),
		Secrets: []*framework.Secret{
			secretAPIToken(b),
		},
		PeriodicFunc:      b.periodic,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walRollbackMinAge,
		Invalidate:        b.invalidate,
		Clean:             func(context.Context) { b.resetClient() },
		RunningVersion:    Version,
	}
	return b
}

func (b *backend) invalidate(_ context.Context, key string) {
	if key == configPath {
		b.resetClient()
	}
}

func (b *backend) resetClient() {
	b.clientMu.Lock()
	b.client = nil
	b.clientMu.Unlock()
}

// getClient returns a client authenticated as the plugin. The caller must
// hold rootLock (for reading or writing).
func (b *backend) getClient(ctx context.Context, s logical.Storage) (*kanidm.Client, *kanidmConfig, error) {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		return nil, nil, errNotConfigured
	}

	b.clientMu.Lock()
	defer b.clientMu.Unlock()
	if b.client != nil {
		return b.client, cfg, nil
	}
	c, err := cfg.newClient(cfg.Token)
	if err != nil {
		return nil, nil, err
	}
	b.client = c
	return c, cfg, nil
}

// randomString returns n lowercase alphanumeric characters.
func randomString(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	for i := range buf {
		// 256 % 36 != 0, so this is very slightly biased; fine for labels.
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}

const backendHelp = `
The Kanidm secrets engine mints Kanidm service account API tokens on demand.
Each token is tied to an OpenBao lease and revoked in Kanidm when the lease
ends; the token's own Kanidm expiry is a backstop.

Configure the engine with "config", define roles with "roles/<name>", then
read "api-token/<name>" to get a token.
`
