#!/usr/bin/env bash
# Bootstrap the Kanidm secrets engine. Idempotent: safe to re-run, and
# re-running is also the recovery path when the plugin's token is lost.
#
# Afterwards no person or file holds a Kanidm credential: the idm_admin
# password lives only in this script's memory, and the plugin's first token
# is rotated away before the script exits.
#
# Requirements: bash, a logged-in OpenBao CLI (BAO_ADDR/BAO_TOKEN with
# rights on sys/mounts, sys/policies and the mount), and the kanidm CLI.
# Each tool is configurable so it can run inside containers:
#
#   KANIDM_RECOVER   command printing a new idm_admin password
#                    (default: docker compose exec -T kanidm kanidmd recover-account idm_admin)
#   KANIDM_CLI       kanidm CLI (default: kanidm). It must already know the
#                    Kanidm URL and CA (KANIDM_URL / KANIDM_CA_PATH).
#   BAO_CLI          OpenBao CLI (default: bao)
#
# Settings:
#   KANIDM_PLUGIN_URL  Kanidm URL as the plugin (inside OpenBao) reaches it. Required.
#   KANIDM_CA_FILE     PEM file with Kanidm's CA, read here and stored in config. Optional.
#   MOUNT              mount path (default: kanidm)
#   PLUGIN_VERSION     plugin version to mount (default: v0.1.0)
#   TOFU_GROUPS        Kanidm groups the tofu account belongs to (space separated)
#   MAILER_GROUPS      Kanidm groups for mailer (default: idm_people_on_boarding)
#   ROTATION_PERIOD    automatic rotation of the plugin token (default: 0, manual)
#   VERBOSE            set to print each kanidm and bao command
set -euo pipefail

: "${KANIDM_PLUGIN_URL:?KANIDM_PLUGIN_URL is required}"
MOUNT=${MOUNT:-kanidm}
PLUGIN_VERSION=${PLUGIN_VERSION:-v0.1.0}
TOFU_GROUPS=${TOFU_GROUPS:-}
MAILER_GROUPS=${MAILER_GROUPS:-idm_people_on_boarding}
ROTATION_PERIOD=${ROTATION_PERIOD:-0}

read -r -a recover_cmd <<<"${KANIDM_RECOVER:-docker compose exec -T kanidm kanidmd recover-account idm_admin}"
read -r -a kanidm_cmd <<<"${KANIDM_CLI:-kanidm}"
read -r -a bao_cmd <<<"${BAO_CLI:-bao}"

ISSUERS=openbao-token-issuers
PLUGIN_ACCOUNT=openbao-kanidm

log() { printf '==> %s\n' "$*" >&2; }

# Everything the kanidm CLI does runs as idm_admin; the password goes in
# through the environment, never argv.
# VERBOSE=1 prints each kanidm and bao call; secrets never appear in argv.
trace() { if [[ -n ${VERBOSE:-} ]]; then printf '    + %s\n' "$*" >&2; fi; }
kanidm() {
	trace kanidm "$@"
	KANIDM_PASSWORD=${ADMIN_PASSWORD:-} "${kanidm_cmd[@]}" "$@" -D idm_admin
}
bao() {
	trace bao "$@"
	"${bao_cmd[@]}" "$@"
}
# `kanidm ... get` exits 0 even when nothing matches, so look for the
# entry's name in the output instead.
exists() { # group|service-account name
	kanidm "$1" get "$2" 2>/dev/null | grep -q "^name: $2\$"
}

cleanup() {
	# The CLI caches a session token on disk; drop it.
	if [[ -n ${ADMIN_PASSWORD:-} ]]; then
		kanidm logout >/dev/null 2>&1 || true
	fi
	unset ADMIN_PASSWORD PLUGIN_TOKEN
}
trap cleanup EXIT

# 1-2. A fresh idm_admin password, kept in memory only.
log "recovering idm_admin"
ADMIN_PASSWORD=$("${recover_cmd[@]}" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | sed -n 's/.*new_password: "\(.*\)".*/\1/p' | tail -n1)
[[ -n $ADMIN_PASSWORD ]] || { echo "could not read the new idm_admin password" >&2; exit 1; }
export ADMIN_PASSWORD
# kanidm() reads the variable at call time; the CLI picks it up as
# KANIDM_PASSWORD.
KANIDM_PASSWORD=$ADMIN_PASSWORD "${kanidm_cmd[@]}" login -D idm_admin >/dev/null

# 3. Groups and accounts, skipping any that exist.
if ! exists group "$ISSUERS"; then
	log "creating group $ISSUERS"
	kanidm group create "$ISSUERS" >/dev/null
fi

ensure_account() { # name display-name
	if ! exists service-account "$1"; then
		log "creating service account $1"
		kanidm service-account create "$1" "$2" "$ISSUERS" >/dev/null
	else
		local managed
		managed=$(kanidm service-account get "$1" 2>/dev/null | sed -n 's/^entry_managed_by: //p')
		case $managed in
		"$ISSUERS"@*) ;;
		"")
			# Once an account is in a privileged group (e.g. mailer in
			# idm_people_on_boarding), idm_admin can neither see nor
			# change this attribute. It was set when the account was
			# created, so leave it.
			log "cannot see entry_managed_by on $1 (privileged account); leaving it as is"
			;;
		*)
			log "setting entry_managed_by on $1 (was $managed)"
			kanidm service-account update "$1" --entry-managed-by "$ISSUERS" >/dev/null
			;;
		esac
	fi
}
ensure_member() { # group account
	kanidm group add-members "$1" "$2" >/dev/null
}

ensure_account "$PLUGIN_ACCOUNT" "OpenBao Kanidm secrets engine"
ensure_member "$ISSUERS" "$PLUGIN_ACCOUNT"
ensure_account tofu "OpenTofu"
for g in $TOFU_GROUPS; do ensure_member "$g" tofu; done
ensure_account mailer "Onboarding mailer"
for g in $MAILER_GROUPS; do ensure_member "$g" mailer; done

# 4. One token for the plugin. Only an account's entry_managed_by may mint
# its tokens, so hand the account to idm_admins for the moment it takes.
log "minting the plugin's first token"
kanidm service-account update "$PLUGIN_ACCOUNT" --entry-managed-by idm_admins >/dev/null
PLUGIN_TOKEN=$(kanidm service-account api-token generate "$PLUGIN_ACCOUNT" "bootstrap-$(date +%s)" --readwrite 2>/dev/null | tail -n1 | tr -d '[:space:]')
kanidm service-account update "$PLUGIN_ACCOUNT" --entry-managed-by "$ISSUERS" >/dev/null
# The CLI exits 0 on most errors, so check the output looks like a token.
[[ $PLUGIN_TOKEN =~ ^[A-Za-z0-9._-]{40,}$ ]] || { echo "could not mint the plugin token" >&2; exit 1; }

# 5. Mount and configure. The token goes in on stdin, never argv.
if ! bao secrets list -format=json | grep -q "\"$MOUNT/\""; then
	log "enabling $MOUNT/"
	bao secrets enable -path="$MOUNT" -plugin-version="$PLUGIN_VERSION" kanidm >/dev/null
fi
ca_args=()
if [[ -n ${KANIDM_CA_FILE:-} ]]; then
	ca_args=("ca_cert=$(cat "$KANIDM_CA_FILE")")
fi
log "writing $MOUNT/config"
printf '%s' "$PLUGIN_TOKEN" | bao write "$MOUNT/config" url="$KANIDM_PLUGIN_URL" token=- \
	rotation_period="$ROTATION_PERIOD" "${ca_args[@]}" >/dev/null
unset PLUGIN_TOKEN

# 6. Rotate the bootstrap token away. (Kanidm keeps accepting a deleted
# token until 5 minutes after it was issued; after that it is dead.)
log "rotating the plugin's token"
bao write -f "$MOUNT/config/rotate-root" >/dev/null

# 7. Roles and policies.
log "writing roles and policies"
bao write "$MOUNT/roles/tofu" service_account=tofu read_write=true ttl=30m max_ttl=30m renewable=false >/dev/null
bao write "$MOUNT/roles/mailer" service_account=mailer read_write=true ttl=12h max_ttl=12h renewable=false >/dev/null
printf 'path "%s/api-token/tofu" {\n  capabilities = ["read"]\n}\n' "$MOUNT" | bao policy write kanidm-tofu - >/dev/null
printf 'path "%s/api-token/mailer" {\n  capabilities = ["read"]\n}\n' "$MOUNT" | bao policy write kanidm-mailer - >/dev/null
cat <<EOF | bao policy write kanidm-operator - >/dev/null
path "$MOUNT/config" {
  capabilities = ["create", "read", "update", "delete"]
}
path "$MOUNT/config/rotate-root" {
  capabilities = ["update"]
}
path "$MOUNT/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "$MOUNT/roles" {
  capabilities = ["list"]
}
path "$MOUNT/tidy" {
  capabilities = ["update"]
}
EOF

# 8. cleanup() logs out and unsets the password.
log "done"
