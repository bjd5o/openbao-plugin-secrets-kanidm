# openbao-plugin-secrets-kanidm

An OpenBao secrets engine that mints Kanidm service account API tokens on
demand. Each token is tied to an OpenBao lease and deleted in Kanidm when
the lease ends; the token's own Kanidm expiry is the backstop. The only
long-lived Kanidm credential is the plugin's own, held in OpenBao storage
and rotated by the plugin (`config/rotate-root`).

Tested against Kanidm 1.11.2 and OpenBao 2.7.1.

## How it works

A read of `kanidm/api-token/<role>`:

1. writes a WAL entry naming the role's service account and a fresh label,
   `bao-<mount id>-<role>-<random>`;
2. calls `POST /v1/service_account/{id}/_api_token` with that label, the
   role's `read_write` flag, and an expiry of issue time + `max_ttl` +
   `expiry_buffer`;
3. lists the account's tokens to find the new token's `token_id`;
4. records `tokens/<token_id>` in plugin storage, deletes the WAL entry,
   and returns the token under a lease.

When the lease is revoked or expires, the plugin calls
`DELETE /v1/service_account/{id}/_api_token/{token_id}` (a 404 counts as
success). If anything fails between mint and response, the token is cleaned
up straight away when Kanidm allows it, and otherwise by WAL rollback about
a minute later.

An hourly tidy (also `kanidm/tidy`) deletes tokens that carry this mount's
label prefix but have no lease record, and drops records past their expiry.
It never touches tokens without the prefix, the plugin's current token, or
tokens less than 6 minutes old (they may be mid-issue). Older plugin tokens
left behind by a rotation whose revoke failed are revoked too.

> **Kanidm's grace window.** Kanidm keeps accepting a deleted API token
> until 5 minutes after that token was *issued* (`AUTH_TOKEN_GRACE_WINDOW`,
> for replication). Revoking a lease removes the token from Kanidm at once,
> but a token revoked within 5 minutes of issue keeps working until that
> 5-minute mark. Tokens older than that die immediately.

## API

| Path | Operations | Fields |
| --- | --- | --- |
| `config` | read, write, delete | `url`, `token` (write-only), `ca_cert`, `request_timeout` (30s), `expiry_buffer` (5m), `rotation_period` (0 = manual; otherwise at least 10m) |
| `config/rotate-root` | write | — |
| `roles/<name>` | read, write, delete, list | `service_account` (name, SPN or UUID), `read_write` (false), `ttl`, `max_ttl`, `renewable` (false) |
| `api-token/<name>` | read | returns `token`, `token_id`, `service_account`, `expires_at` |
| `tidy` | write | — returns `revoked_tokens`, `expired_records` |

- **config** writes check the token with `GET /v1/self` before saving, and
  reject read-only tokens. Reads return everything except the token, plus
  `label_prefix`, the plugin's `service_account`, `token_id` and
  `token_issued_at`. Writing a new token deletes the previous one in
  Kanidm (with the new token). The label prefix is generated on first write and kept
  across config deletes, so tidy keeps recognising this mount's tokens.
- **rotate-root** mints a new token for the plugin's own account, checks it
  with `/v1/self`, saves it, then deletes the old token using the new one.
  If that delete fails, the new token is kept and the response carries a
  warning naming the old token. Rotation holds a lock, so it never races a
  request using the old token. With `rotation_period` set, the periodic
  function rotates once the token is older than that.
- **roles**: `ttl` must not exceed `max_ttl`. For a non-renewable role, `ttl`
  is forced to `max_ttl` (if only `ttl` is given, `max_ttl` follows it).
  Unset values fall back to the mount's default and max lease TTLs.
  Renewal extends by `ttl` but never past `max_ttl` from issue, and never
  past the `max_ttl` in force when the token was minted.

## Build and package

```sh
make test              # vet + unit tests (fake Kanidm)
make build             # static binary in dist/
make release           # linux amd64/arm64 binaries + SHA256SUMS in dist/release
make image             # OpenBao image with the plugin baked in
make integration       # real Kanidm + OpenBao in Docker, about 12 minutes
```

The `Dockerfile` builds the plugin with `CGO_ENABLED=0` and copies it into
`/openbao/plugins` of the OpenBao image; its SHA-256 is printed in the build
log and saved next to the binary as
`/openbao/plugins/openbao-plugin-secrets-kanidm.sha256`.

Register it declaratively in the OpenBao server config
(`deploy/openbao.hcl`):

```hcl
plugin_directory = "/openbao/plugins"

plugin "secret" "kanidm" {
  command   = "openbao-plugin-secrets-kanidm"
  version   = "v0.1.0"
  sha256sum = "<sha256 of the binary>"
}
```

OpenBao registers declared plugins at startup and on SIGHUP. The `version`
must match the version built into the binary (`VERSION` build arg /
`make ... VERSION=`).

**Upgrades:** build with the new `VERSION`, update `version` and
`sha256sum`, rebuild the image and restart, then

```sh
bao secrets tune -plugin-version=<new> kanidm/
bao plugin reload -plugin kanidm
```

Leases from older versions keep revoking: revocation only needs the lease's
internal `service_account` (UUID) and `token_id`, which stay stable.

## Kanidm permissions

The plugin has no admin role. Kanidm only lets an account's
`entry_managed_by` mint its API tokens, so:

| Entity | Kind | Setting |
| --- | --- | --- |
| `openbao-token-issuers` | group | — |
| `openbao-kanidm` | service account | member of `openbao-token-issuers`; `entry_managed_by = openbao-token-issuers` (so rotate-root can mint its replacement) |
| `tofu` | service account | `entry_managed_by = openbao-token-issuers`; its admin groups |
| `mailer` | service account | `entry_managed_by = openbao-token-issuers`; member of `idm_people_on_boarding` |

Every service account the engine serves must name `openbao-token-issuers`
in `entry_managed_by`; Tofu sets this on the accounts it creates.
`idm_people_on_boarding` is enough for the mailer to create credential
reset tokens for ordinary people (not for high-privilege ones, which need
`idm_service_desk` or above). Being `entry_managed_by` gives the plugin
broader control over those accounts than token minting; and since it can
mint tokens for `tofu`, a compromised OpenBao means a compromised Kanidm.

## Bootstrap

`scripts/bootstrap.sh` does the whole sequence and is idempotent:

1. recovers `idm_admin` (`kanidmd recover-account`) and keeps the password
   in memory only;
2. creates the group and the three service accounts (skipping existing
   ones);
3. mints one token for `openbao-kanidm` (handing the account to
   `idm_admins` for that moment only, since idm_admin is not in the issuers
   group);
4. enables the mount and writes `kanidm/config` (token on stdin);
5. runs `rotate-root`, so the bootstrap token is deleted;
6. writes roles `tofu` and `mailer` and the policies `kanidm-tofu`,
   `kanidm-mailer` and `kanidm-operator`;
7. logs the kanidm CLI out and unsets the password.

```sh
export BAO_ADDR=https://bao.example.com BAO_TOKEN=...   # operator token
KANIDM_PLUGIN_URL=https://idm.example.com \
KANIDM_CLI="docker compose exec -T -e KANIDM_PASSWORD kanidm-tools kanidm" \
KANIDM_RECOVER="docker compose exec -T kanidm kanidmd recover-account idm_admin" \
TOFU_GROUPS="idm_admins" \
  scripts/bootstrap.sh
```

See the header of the script for every setting. Re-running it is also the
recovery path when the plugin's token is lost or revoked.

**Break-glass:**

| Failure | Recovery |
| --- | --- |
| Kanidm needs fixing and Tofu can't get a token | `kanidmd recover-account idm_admin` in the container, fix by hand |
| Kanidm is down, so OpenBao OIDC login fails | a non-OIDC auth method for the operator (e.g. cert auth), or `bao operator generate-root` |
| Plugin token lost or revoked | re-run `scripts/bootstrap.sh` |

## Consumers

| Role | `ttl` | `max_ttl` | `renewable` | `read_write` | Policy |
| --- | --- | --- | --- | --- | --- |
| `tofu` | 30m | 30m | false | true | `kanidm-tofu` (read `kanidm/api-token/tofu`) |
| `mailer` | 12h | 12h | false | true | `kanidm-mailer` (read `kanidm/api-token/mailer`) |

**OpenTofu** reads a token per run through an ephemeral resource, so it
never reaches state or plan:

```hcl
ephemeral "vault_generic_secret" "kanidm" {
  path = "kanidm/api-token/tofu"
}

provider "kanidm" {
  url   = "https://idm.example.com"
  token = ephemeral.vault_generic_secret.kanidm.data.token
}
```

The ephemeral read neither renews nor revokes its lease, so each token
lives the full `ttl`. Keep `ttl` above your longest apply, or wrap runs in a
script that calls `bao lease revoke` afterwards.

**Mailer:** an OpenBao Agent template renders the token to a file, and
Agent fetches a new one as the lease nears its end:

```hcl
template {
  contents    = "{{ with secret \"kanidm/api-token/mailer\" }}{{ .Data.token }}{{ end }}"
  destination = "/run/secrets/kanidm-token"
  perms       = "0400"
}
```

The mailer must re-read the file on each run instead of caching the token.

## Testing

- **Unit** (`go test ./...`): the backend with in-memory storage against an
  `httptest` fake of the four Kanidm calls with injectable faults. Covers
  config validation, role rules, issue, revoke (including 404), renew caps,
  non-renewable leases, inline cleanup and WAL rollback after failures
  following the POST (including a timeout where Kanidm minted but never
  answered), tidy scope, and rotate-root ordering and failure handling.
- **Integration** (`make integration`): Kanidm and a Raft-backed OpenBao in
  Docker, plugin registered declaratively, bootstrapped twice with
  `scripts/bootstrap.sh`. Covers token use, `bao lease revoke`, lease
  expiry, renewal up to `max_ttl`, rotate-root, an OpenBao restart with
  live leases, tidy, and WAL rollback after the plugin process is killed
  between mint and response. The last uses a test-only build tag
  (`-tags faulthook`): roles named `fault-crash-after-mint*` make the
  plugin exit right after minting. Never ship a `faulthook` build.
