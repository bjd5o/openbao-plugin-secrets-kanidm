#!/usr/bin/env bash
# Run the integration suite: build the plugin into an OpenBao image, start
# Kanidm and OpenBao, bootstrap with scripts/bootstrap.sh, run the Go tests
# tagged "integration", and tear everything down.
#
#   scripts/integration.sh                 # whole suite (about 12 minutes)
#   KEEP=1 scripts/integration.sh          # leave the stack running afterwards
#   GO_TEST_ARGS='-run Revoke' scripts/integration.sh
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=integration/compose.yaml
STATE=$PWD/integration/.state
export ITEST_KANIDM_PORT=${ITEST_KANIDM_PORT:-28443}
export ITEST_BAO_PORT=${ITEST_BAO_PORT:-28200}
BAO=http://127.0.0.1:$ITEST_BAO_PORT

dc() { docker compose -f "$COMPOSE" "$@"; }
log() { printf '==> %s\n' "$*" >&2; }

finish() {
	status=$?
	dc logs --no-color openbao >"$STATE/openbao.log" 2>&1 || true
	dc logs --no-color kanidm >"$STATE/kanidm.log" 2>&1 || true
	if [[ -z ${KEEP:-} ]]; then
		dc down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	if [[ $status -ne 0 ]]; then
		log "failed; logs in $STATE"
	fi
	exit $status
}

rm -rf "$STATE"
mkdir -p "$STATE"
dc down -v --remove-orphans >/dev/null 2>&1 || true
trap finish EXIT

log "building and starting the stack"
dc build openbao
dc up -d

wait_for() { # description url [curl args...]
	local what=$1 url=$2
	shift 2
	for _ in $(seq 1 90); do
		if curl -s -o /dev/null "$@" "$url"; then return 0; fi
		sleep 1
	done
	log "timed out waiting for $what"
	return 1
}
wait_for kanidm "https://127.0.0.1:$ITEST_KANIDM_PORT/status" -k --fail
wait_for openbao "$BAO/v1/sys/seal-status" --fail

log "initialising and unsealing OpenBao"
curl -s --fail -X PUT "$BAO/v1/sys/init" -d '{"secret_shares":1,"secret_threshold":1}' >"$STATE/init.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(d["keys_base64"][0]); open(sys.argv[3],"w").write(d["root_token"])' \
	"$STATE/init.json" "$STATE/unseal.key" "$STATE/root.token"
curl -s --fail -X PUT "$BAO/v1/sys/unseal" -d "{\"key\":\"$(cat "$STATE/unseal.key")\"}" >/dev/null
BAO_TOKEN=$(cat "$STATE/root.token")
export BAO_TOKEN

dc exec -T tools cat /data/ca.pem >"$STATE/ca.pem"

run_bootstrap() {
	KANIDM_RECOVER="docker compose -f $COMPOSE exec -T kanidm kanidmd recover-account idm_admin" \
		KANIDM_CLI="docker compose -f $COMPOSE exec -T -e KANIDM_PASSWORD tools kanidm" \
		BAO_CLI="docker compose -f $COMPOSE exec -T -e BAO_TOKEN -e BAO_ADDR=http://127.0.0.1:8200 openbao bao" \
		KANIDM_PLUGIN_URL=https://idm.test:8443 \
		KANIDM_CA_FILE="$STATE/ca.pem" \
		scripts/bootstrap.sh
}
log "bootstrap"
run_bootstrap
log "bootstrap again (idempotency, and the lost-token recovery path)"
run_bootstrap

log "the plugin is registered from the declarative config"
curl -s --fail -H "X-Vault-Token: $BAO_TOKEN" "$BAO/v1/sys/plugins/catalog/secret/kanidm?version=v0.1.0" >"$STATE/catalog.json"

# An observer account lets the tests inspect tokens in Kanidm without
# the plugin's credential. It is managed by idm_admins so idm_admin can
# mint its token, and is in the issuers group so it can list and mint.
log "creating the test observer"
ADMIN_PASSWORD=$(dc exec -T kanidm kanidmd recover-account idm_admin 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | sed -n 's/.*new_password: "\(.*\)".*/\1/p' | tail -n1)
export KANIDM_PASSWORD=$ADMIN_PASSWORD
k() { dc exec -T -e KANIDM_PASSWORD tools kanidm "$@" -D idm_admin; }
k login >/dev/null
k service-account create itest-observer "Integration test observer" idm_admins >/dev/null
k group add-members openbao-token-issuers itest-observer >/dev/null
k service-account api-token generate itest-observer observer --readwrite 2>/dev/null | tail -n1 | tr -d '[:space:]' >"$STATE/observer.token"
k logout >/dev/null
unset KANIDM_PASSWORD ADMIN_PASSWORD

log "running the integration tests"
ITEST_STATE=$STATE ITEST_COMPOSE=$PWD/$COMPOSE ITEST_BAO_ADDR=$BAO \
	ITEST_KANIDM_ADDR=127.0.0.1:$ITEST_KANIDM_PORT ITEST_KANIDM_NAME=idm.test \
	go test -tags integration -count=1 -v -timeout 30m ${GO_TEST_ARGS:-} ./integration/
