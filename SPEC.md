# OpenBao Kanidm Secrets Engine — Implementation Plan

Oct 16, 2026 · @bjd

## Goals and non-goals

Build an OpenBao secrets engine plugin that mints Kanidm service account API tokens on demand, ties each one to an OpenBao lease, and revokes it in Kanidm when the lease ends. The only long-lived Kanidm credential left is the plugin's own, held in OpenBao storage and rotated by the plugin.

**Goals**

- Consumers read `kanidm/api-token/<role>` and get a fresh, short-lived API token for the role's service account.
- Every token is revoked by the plugin when its lease expires or is revoked, with the token's own Kanidm expiry as a backstop.
- OpenTofu gets its Kanidm token per run, so no Tofu credential is stored anywhere.
- The onboarding mailer gets its token from OpenBao instead of holding a long-lived one.
- The plugin's own credential is never seen by a person after bootstrap (`rotate-root`).

**Non-goals**

- Credential reset tokens for people. The mailer mints those itself with the token it gets from this engine.
- OAuth2 client secrets. Those stay with the Tofu provider fork (ephemeral read, kept out of state).
- Creating or managing service accounts. Tofu owns accounts and their `entry_managed_by`; the engine only mints and revokes tokens.
- Multi-tenant or multi-Kanidm support. One mount talks to one Kanidm instance.

## Architecture

The engine is a standard OpenBao dynamic-secrets plugin. A read of `api-token/<role>` mints a Kanidm API token and returns it under a lease; when the lease ends, OpenBao calls the plugin's revoke callback, which deletes the token in Kanidm.

&#91;embedded content: issue and revoke sequence · 4 parties\]

The plugin talks to Kanidm only with its own token; consumers never touch the plugin directly, and the Kanidm expiry catches anything revocation misses.

**Issue path**

1. The consumer logs in to OpenBao (OIDC for Tofu, AppRole or cert auth for the mailer) and reads `kanidm/api-token/<role>`.
2. The plugin loads its config and the role, then writes a write-ahead log (WAL) entry naming the service account and a unique label, `bao-<random>`.
3. It calls `POST /v1/service_account/{id}/_api_token` with that label, the role's `read_write` flag and an expiry. Kanidm returns only the token string.
4. It lists the account's tokens and matches the label to get the `token_id`, which revocation needs.
5. It deletes the WAL entry and returns the token. The lease's internal data holds the service account, `token_id` and label.

**End of a lease**

- Expiry or `bao lease revoke` → revoke callback → `DELETE /v1/service_account/{id}/_api_token/{token_id}`. A 404 counts as success, since the token is already gone.
- Renewal (renewable roles only) extends the lease by `ttl`, never past `max_ttl` from issue.
- If revocation keeps failing, OpenBao retries it; the token's Kanidm expiry kills it regardless.

**Lifetimes**

| Setting | Set where | Controls |
| --- | --- | --- |
| `ttl` | Role | Lease length at issue and per renewal |
| `max_ttl` | Role | Hard cap on the lease, counted from issue |
| Token expiry | Plugin, at mint | Issue time + `max_ttl` + a small buffer (default 5 min), so normal revocation always runs first |
| `renewable` | Role | Off → `ttl` = `max_ttl` and clients fetch a new token instead of renewing |

**Kanidm API used**

| Method | Path | Used for |
| --- | --- | --- |
| `POST` | `/v1/service_account/{id}/_api_token` | Mint (body: `label`, `expiry`, `read_write`; returns the token string) |
| `GET` | `/v1/service_account/{id}/_api_token` | Find a token's `token_id` by label; tidy; rollback |
| `DELETE` | `/v1/service_account/{id}/_api_token/{token_id}` | Revoke |
| `GET` | `/v1/self` | Check the plugin's own token (config write, `rotate-root`) |

## API surface

Eight paths under the mount (`kanidm/` below). Only `api-token/` returns a secret; `config/token` accepts the plugin's token but never returns it.

| Path | Operations | Fields | Notes |
| --- | --- | --- | --- |
| `config` | read, write, delete | `request_timeout` (30s), `expiry_buffer` (default 5m), `rotation_period` (0 = manual only) | Reads return the origin stored at `config/url`. Delete also removes `config/url`, `config/ca`, and `config/token` |
| `config/url` | read, write, delete | `url` | Kanidm origin |
| `config/ca` | read, write, delete | `ca_cert` | PEM bundle used instead of the system roots. Delete to go back to the system roots |
| `config/token` | read, write, delete | `token` (write-only) | Write calls `GET /v1/self` with the token before saving. The token is seal-wrapped at this path. Reads return `token_id` and `token_issued_at` |
| `config/rotate-root` | write | none | Mints a new token for the plugin's own account, saves it, revokes the old one |
| `roles/<name>` | read, write, delete, list | `service_account` (name or UUID), `read_write` (default false), `ttl`, `max_ttl`, `renewable` (default false) | Write rejects `ttl` > `max_ttl`; non-renewable forces `ttl` = `max_ttl` |
| `api-token/<name>` | read | — | Returns `token`, `token_id`, `service_account`, `expires_at`, under a lease |
| `tidy` | write | none | Runs the cleanup the periodic function runs, on demand |

Policies follow the path layout: Tofu gets `read` on `kanidm/api-token/tofu`, the mailer on `kanidm/api-token/mailer`, and only the operator policy touches `config` and `roles`.

## Implementation phases

Seven phases, about 5 to 7 working days in total; a usable MVP (phases 0 to 3) lands in roughly 2.5 days. Each phase ends in something runnable against a real Kanidm.

### Phase 0: Spikes (0.5 day)

- [x] Confirm a service account can have `entry_managed_by` set to a group the plugin's account belongs to, including the plugin's own account (needed for `rotate-root`)
- [x] Mint a token with `curl` and confirm the `expiry` format Kanidm accepts and that `GET …/_api_token` shows the label
- [x] Confirm your OpenBao version accepts a declarative `plugin "secret" "kanidm"` block with `command`

Done when: each question above has a yes/no written into Open questions.

### Phase 1: Skeleton and Kanidm client (0.5 day)

- [x] Go module on `github.com/openbao/openbao/sdk/v2`; `main.go` calls `plugin.ServeMultiplex`
- [x] `framework.Backend` with `Paths`, `Secrets`, `PeriodicFunc`, `WALRollback` and `WALRollbackMinAge` wired (handlers stubbed)
- [x] Kanidm client: the four calls from Architecture, custom CA, request timeout, a typed `ErrNotFound` for 404

Done when: the plugin registers and mounts, and the client's calls pass against a local Kanidm.

### Phase 2: Config and roles (0.5 day)

- [x] `config` and `config/token`; token writes validate with `GET /v1/self`; `token` never returned on read
- [x] A per-mount label prefix (`bao-<6 random chars>-`) generated on first config write and stored, so tidy only touches this mount's tokens
- [x] `roles/<name>` CRUD and list, with the `ttl`/`max_ttl`/`renewable` rules from API surface

Done when: config and roles round-trip and bad input is rejected with clear errors.

### Phase 3: Token issue, revoke, renew (1 day)

- [x] `api-token/<name>` read: mint, find `token_id` by label, record `tokens/<token_id>` in plugin storage, return under a lease
- [x] `framework.Secret` with `Revoke` (DELETE, 404 = success, then remove the `tokens/` record) and `Renew` (only when the role is renewable; cap at `max_ttl`)
- [x] Expiry on the Kanidm token = issue time + `max_ttl` + `expiry_buffer`

Done when: read, `bao lease revoke` and lease expiry each leave Kanidm in the right state. This is the MVP.

### Phase 4: WAL rollback (0.5 to 1 day)

- [x] Before minting, `framework.PutWAL` with the service account and label; after the lease is recorded, `DeleteWAL`
- [x] `WALRollback`: list the account's tokens, delete any with the WAL's label; `WALRollbackMinAge` about 1 minute

Done when: killing the plugin between mint and response leaves no stray token after the rollback runs.

### Phase 5: Tidy (0.5 day)

- [x] For each role's service account, revoke tokens carrying this mount's prefix that have no `tokens/` record
- [x] Drop `tokens/` records whose expiry has passed
- [x] Run from `PeriodicFunc` (rate-limited to, say, hourly) and from `tidy`

Done when: a token minted by hand with the mount's prefix disappears on the next tidy, and tokens without the prefix are never touched.

### Phase 6: rotate-root (0.5 to 1 day)

- [x] `config/rotate-root`: mint a new token for the plugin's own account, check it with `/v1/self`, save it, then revoke the old one with the new token
- [x] A lock so rotation never races a token read using the old token
- [x] Automatic rotation from `PeriodicFunc` when `rotation_period` is set and the token is older than it

Done when: after rotation, the old token gets 401 and token reads still work.

### Phase 7: Hardening and release (1 to 2 days)

- [x] Integration test suite in CI (see Testing)
- [x] Static `CGO_ENABLED=0` build, SHA-256 published with each release
- [x] README covering bootstrap, policies and the role settings per consumer

## Kanidm permission model

The plugin gets no admin role. Its power comes from one group: Kanidm lets only a service account's `entry_managed_by` entity mint API tokens for it, so every account the engine serves names that group.

| Entity | Kind | Membership or setting | Why |
| --- | --- | --- | --- |
| `openbao-kanidm` | Service account | Member of `openbao-token-issuers` | The plugin's own identity |
| `openbao-token-issuers` | Group | — | The `entry_managed_by` target for every account the engine serves |
| `tofu` | Service account | `entry_managed_by = openbao-token-issuers`; its admin groups as today | Tofu's Kanidm identity, tokens per run |
| `mailer` | Service account | `entry_managed_by = openbao-token-issuers`; the smallest group that can create credential reset tokens | Onboarding emails |
| `openbao-kanidm` (again) | Service account | `entry_managed_by = openbao-token-issuers` | Lets `rotate-root` mint its own replacement (Phase 0 spike) |

- Tofu sets `entry_managed_by` on every service account it creates; `tofu` and `openbao-kanidm` themselves are created at bootstrap.
- Being `entry_managed_by` lets the plugin manage those accounts more broadly than minting tokens. That is acceptable because the scope is limited to accounts listed here.
- The plugin can mint tokens for `tofu`, which administers Kanidm. A compromised OpenBao therefore means a compromised Kanidm. OpenBao is already your root of trust, so this adds no new trust, but it is the reason the break-glass path in Bootstrap matters.

## Testing

Two layers: fast unit tests against a fake Kanidm, and an integration suite against real Kanidm and OpenBao containers. The failure cases matter more than the happy path, because they are where tokens leak.

| Layer | Setup | Cases |
| --- | --- | --- |
| Unit | The backend with in-memory storage; an `httptest` server implementing the four Kanidm calls, with injectable errors and delays | Config validation; role `ttl`/`max_ttl` rules; token issue happy path; revoke on 404; renew capped at `max_ttl`; non-renewable leases refuse renewal; WAL rollback after a failure following the POST; tidy only touching this mount's prefix; `rotate-root` saving the new token before revoking the old, and keeping the new one when the revoke fails |
| Integration | Kanidm container (bootstrapped with `kanidmd recover-account idm_admin`), OpenBao dev server with the plugin in its plugin directory | Token from `api-token/` works against `/v1/self`; `bao lease revoke` → token gets 401; a 1-minute `ttl` lease expires → 401; renewable role renews then stops at `max_ttl`; `rotate-root` → old plugin token gets 401, token reads still work; restart OpenBao mid-test and leases still revoke |

A test-only build tag can add a fault hook ("crash after mint") to exercise WAL rollback end to end without killing processes by hand.

## Packaging and deployment

Ship the plugin as a static binary baked into your OpenBao image and register it declaratively in OpenBao's config, so a fresh container comes up with the plugin already in the catalog.

1. Build with `CGO_ENABLED=0` and record the binary's SHA-256.
2. Extend the OpenBao image in the Compose stack: copy the binary into the directory named by `plugin_directory`.
3. Declare it in the OpenBao server config:

```hcl
plugin_directory = "/openbao/plugins"

plugin "secret" "kanidm" {
  command   = "openbao-plugin-secrets-kanidm"
  version   = "v0.1.0"
  sha256sum = "<sha256 of the binary>"
}
```

4. OpenBao registers declared plugins at startup and on SIGHUP (`plugin_auto_register` defaults to true).
5. Enable the mount at bootstrap, not from Tofu: `bao secrets enable -path=kanidm -plugin-version=v0.1.0 kanidm`. Tofu gets its own Kanidm token from this mount, so it can't be the thing that creates it.

**Upgrades**: build, update `version` and `sha256sum`, rebuild the image, restart; then `bao secrets tune -plugin-version=<new> kanidm/` and `bao plugin reload -plugin kanidm`. Leases issued by the old version keep working, because revocation only needs `token_id` and the service account from the lease data, so keep that format stable across versions.

OpenBao can also pull plugins from OCI images (`image` instead of `command`), but for one self-built plugin, baking it into your own image is simpler.

## Bootstrap sequence

One idempotent script run, after which no person or file holds a Kanidm credential: the admin password lives only in the script's memory, and the plugin's first token is rotated away before the script exits.

1. Start Kanidm and OpenBao, and unseal OpenBao.
2. Run `kanidmd recover-account idm_admin` inside the Kanidm container; keep the printed password in a shell variable only.
3. As `idm_admin`, create (skipping any that exist):
   - group `openbao-token-issuers`;
   - service account `openbao-kanidm`, added to that group, `entry_managed_by` the group;
   - service accounts `tofu` and `mailer`, `entry_managed_by` the group, plus their own permission groups.
4. Mint one API token for `openbao-kanidm`.
5. `bao secrets enable -path=kanidm kanidm`, then write `kanidm/config`, `kanidm/config/url` with the Kanidm origin, `kanidm/config/ca` with the CA when Kanidm's certificate is not signed by a system root, and `kanidm/config/token` with that token.
6. `bao write -f kanidm/config/rotate-root`. The token from step 4 is now revoked.
7. Write roles `kanidm/roles/tofu` and `kanidm/roles/mailer` and their OpenBao policies.
8. Unset the password variable and exit.

**Break-glass**, for when the normal path is down:

| Failure | Recovery |
| --- | --- |
| Kanidm needs fixing and Tofu can't get a token | `kanidmd recover-account idm_admin` in the container, fix by hand |
| Kanidm is down, so OpenBao OIDC login fails | A non-OIDC OpenBao auth method for the operator (cert auth with your YubiKey), or `bao operator generate-root` |
| Plugin token lost or revoked | Re-run steps 2, 4, 5 and 6 |

## Consumer integration

Tofu reads a non-renewable token per run; the mailer gets one through an OpenBao Agent template that fetches a new token before the old one expires.

| Role | `ttl` | `max_ttl` | `renewable` | `read_write` | How the consumer logs in to OpenBao |
| --- | --- | --- | --- | --- | --- |
| `tofu` | 30m | 30m | false | true | You, through OIDC (`bao login -method=oidc`) |
| `mailer` | 12h | 12h | false | true | AppRole bound to the Compose network, or cert auth |

**OpenTofu**: an ephemeral read feeds the kanidm provider, so the token never reaches state or plan.

```hcl
ephemeral "vault_generic_secret" "kanidm" {
  path = "kanidm/api-token/tofu"
}

provider "kanidm" {
  url   = "https://idm.example.com"
  token = ephemeral.vault_generic_secret.kanidm.data.token
}
```

The vault provider's ephemeral read neither renews nor revokes its lease, so each Tofu token lives the full 30 minutes. Set `ttl` above your longest apply, or wrap runs in a script that calls `bao lease revoke` afterwards.

**Mailer**: an Agent template renders the token to a file the mailer reads on each run; Agent fetches a new one as expiry approaches. The mailer must re-read the file rather than cache the token at startup.

## Open questions and risks

**To answer in Phase 0 or along the way**

- [x] Can `openbao-kanidm` be `entry_managed_by` a group it belongs to, so it can mint its own replacement? If not, `rotate-root` needs a second account or stays manual.
  - **Yes** (Kanidm 1.11.2). It mints its own replacement and deletes the old token. Note that `idm_admin` is *not* in that group, so it cannot mint for the account; bootstrap sets `entry_managed_by = idm_admins` for the moment it mints the first token, then sets it back.
- [x] What `expiry` format does the mint call accept, and can it be omitted for a token with no expiry?
  - **Unix seconds** (an integer; RFC 3339 strings are rejected with 422). **Yes**, `null` means no expiry. The list call returns `expiry` and `issued_at` as Unix seconds too.
- [x] Does Kanidm enforce unique token labels per account? The random suffix makes collisions unlikely either way.
  - **No**, duplicate labels are accepted. The plugin falls back to the `token_id` in the token's own (JWS) payload if a label ever matches twice.
- [x] Which is the smallest built-in Kanidm group that lets `mailer` create credential reset tokens for people?
  - **`idm_people_on_boarding`**, for ordinary people; it is refused for high-privilege people (`idm_service_desk` covers those). Membership makes `mailer` itself privileged, after which `idm_admin` can no longer read or change its `entry_managed_by`; bootstrap tolerates that.
- [x] Is there a limit on API tokens per service account? Tidy keeps the count low, but a busy role mints one token per read.
  - **None observed**: 120 tokens on one account minted and listed without error.
- [x] Does OpenBao (2.7.1) accept a declarative `plugin "secret" "kanidm"` block with `command`?
  - **Yes**: the integration stack registers the plugin that way and mounts it with `-plugin-version=v0.1.0`. OpenBao 2.x has no `file` storage backend, so the test stack uses Raft.
- [x] Found along the way: **Kanidm keeps accepting a deleted API token until 5 minutes after it was issued** (`AUTH_TOKEN_GRACE_WINDOW`, for replication). Revocation removes the token at once, but one revoked within 5 minutes of issue keeps working until that mark. Tidy also leaves tokens younger than 6 minutes alone, because they may still be mid-issue.

**Risks**

- OpenBao becomes a hard dependency: if it is down, Tofu and the mailer can't get Kanidm tokens. Break-glass covers Tofu; the mailer simply waits.
- A bug in revoke leaves tokens alive until their Kanidm expiry. The expiry backstop bounds this to `max_ttl` plus the buffer.
- Kanidm API changes between versions would break minting. Pin the Kanidm version in the integration suite and run it before upgrading Kanidm.

## Sources

- [OpenBao: declarative plugins](https://openbao.org/docs/configuration/plugins/)
- [OpenBao SDK (`sdk/framework`: WAL, secrets, periodic functions)](https://github.com/openbao/openbao)
- [Kanidm API: OpenAPI spec bundled with the Kanidm Terraform provider](https://github.com/SeanLatimer/terraform-provider-kanidm)
- [Vault provider: ephemeral `vault_generic_secret`](https://github.com/hashicorp/terraform-provider-vault)
