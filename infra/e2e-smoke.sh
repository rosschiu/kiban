#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Cold-start end-to-end smoke test.
#
#   make dev-clean && make dev
#   -> mint a bearer token via Keycloak's password grant (a temp client + temp user, created
#      here via the Keycloak ADMIN API — the realm import (infra/keycloak-build/realm-kiban.json)
#      ships no client with both directAccessGrantsEnabled AND a "kiban-api" audience mapper,
#      so a throwaway client+user is created at RUNTIME via the admin API instead of changing
#      the realm file).
#   -> GET https://127.0.0.1:8443/api/platform/capabilities through the gateway with that token
#      -> must be 200 with a {"data": ...} envelope.
#
# Requires: docker, make, curl, jq, openssl (uuid/secret generation). Run from the repo root or
# anywhere — paths below are all relative to this script's own location.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

log() { echo "[e2e-smoke] $*" >&2; }
fail() {
  log "FAIL: $*"
  exit 1
}

# --- 0. env — refuses the live stack in PUBLIC mode (infra/proof-env.sh): this script's own
#        step 1 is `make dev-clean && make dev`, which would tear down and rebuild a deployment a
#        human is using. ---
# shellcheck disable=SC1091
. infra/proof-env.sh
proof_env .env

: "${KEYCLOAK_HOST_PORT:?KEYCLOAK_HOST_PORT not set}"
: "${KEYCLOAK_REALM:?KEYCLOAK_REALM not set}"
: "${KC_BOOTSTRAP_ADMIN_USERNAME:?KC_BOOTSTRAP_ADMIN_USERNAME not set}"
: "${KC_BOOTSTRAP_ADMIN_PASSWORD:?KC_BOOTSTRAP_ADMIN_PASSWORD not set}"

kc_base="http://127.0.0.1:${KEYCLOAK_HOST_PORT}"
# See infra/e2e-login.sh's identical comment — same reasoning.
gw_base="https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT:-8443}"

# --- 1. cold start ---
log "cold start: make dev-clean && make dev"
make -C "$repo_root" dev-clean
make -C "$repo_root" dev

log "compose status:"
docker compose --project-directory infra ps

# --- 2. Keycloak admin token (master realm, admin-cli) ---
log "fetching a Keycloak admin token"
admin_token="$(curl -sf -X POST "$kc_base/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KC_BOOTSTRAP_ADMIN_USERNAME" \
  -d "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" \
  | jq -r '.access_token')"
[ -n "$admin_token" ] && [ "$admin_token" != "null" ] || fail "could not obtain a Keycloak admin token"

admin_curl() { curl -sf -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" "$@"; }

realm_url="$kc_base/admin/realms/$KEYCLOAK_REALM"
smoke_client_id="kiban-e2e-smoke"
smoke_client_secret="e2e-smoke-$(openssl rand -hex 16)"
smoke_username="kiban-e2e-smoke-user"
smoke_password="e2e-smoke-$(openssl rand -hex 16)"

# --- 3. temp confidential client: password grant enabled, "kiban-api" audience mapper ---
existing_client_uuid="$(admin_curl "$realm_url/clients?clientId=$smoke_client_id" | jq -r '.[0].id // empty')"
if [ -z "$existing_client_uuid" ]; then
  log "creating temp client $smoke_client_id"
  admin_curl -X POST "$realm_url/clients" -d "$(jq -n \
    --arg id "$smoke_client_id" --arg secret "$smoke_client_secret" '{
      clientId: $id, enabled: true, protocol: "openid-connect",
      publicClient: false, secret: $secret,
      standardFlowEnabled: false, implicitFlowEnabled: false,
      directAccessGrantsEnabled: true, serviceAccountsEnabled: false
    }')" >/dev/null
  client_uuid="$(admin_curl "$realm_url/clients?clientId=$smoke_client_id" | jq -r '.[0].id')"
else
  log "temp client $smoke_client_id already exists, reusing it (resetting its secret)"
  client_uuid="$existing_client_uuid"
  admin_curl -X PUT "$realm_url/clients/$client_uuid" -d "$(jq -n \
    --arg id "$smoke_client_id" --arg secret "$smoke_client_secret" '{
      clientId: $id, enabled: true, protocol: "openid-connect",
      publicClient: false, secret: $secret,
      standardFlowEnabled: false, implicitFlowEnabled: false,
      directAccessGrantsEnabled: true, serviceAccountsEnabled: false
    }')" >/dev/null
fi
[ -n "$client_uuid" ] && [ "$client_uuid" != "null" ] || fail "could not resolve the temp client's id"

mapper_exists="$(admin_curl "$realm_url/clients/$client_uuid/protocol-mappers/models" \
  | jq -r '[.[] | select(.name=="kiban-api-audience")] | length')"
if [ "$mapper_exists" = "0" ]; then
  log "adding a kiban-api audience protocol mapper to the temp client"
  admin_curl -X POST "$realm_url/clients/$client_uuid/protocol-mappers/models" -d '{
    "name": "kiban-api-audience",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "config": {
      "included.custom.audience": "kiban-api",
      "access.token.claim": "true",
      "id.token.claim": "false"
    }
  }' >/dev/null
fi

# --- 4. temp user ---
# Deliberately delete-then-recreate rather than reuse-and-reset-password: a user created
# WITHOUT credentials and given a password afterward via PUT .../reset-password hits a
# real Keycloak 26.6.1 bug in this realm's config — the direct-grant token call then fails
# with error="resolve_required_actions" / "Account is not fully set up" even though the
# user's own requiredActions list is empty and the direct-grant flow is the untouched stock
# one. Creating the user WITH its password credential inline (one call) does not hit this —
# confirmed by hand against the live dev stack before wiring it here.
existing_user_id="$(admin_curl "$realm_url/users?username=$smoke_username&exact=true" | jq -r '.[0].id // empty')"
if [ -n "$existing_user_id" ]; then
  log "temp user $smoke_username already exists, deleting it (recreated fresh below)"
  admin_curl -X DELETE "$realm_url/users/$existing_user_id" >/dev/null
fi

log "creating temp user $smoke_username"
admin_curl -X POST "$realm_url/users" -d "$(jq -n \
  --arg u "$smoke_username" --arg pw "$smoke_password" '{
    username: $u,
    email: ($u + "@example.invalid"),
    firstName: "Kiban", lastName: "E2E Smoke",
    enabled: true, emailVerified: true, requiredActions: [],
    credentials: [{type: "password", value: $pw, temporary: false}]
  }')" >/dev/null
user_id="$(admin_curl "$realm_url/users?username=$smoke_username&exact=true" | jq -r '.[0].id // empty')"
[ -n "$user_id" ] && [ "$user_id" != "null" ] || fail "could not resolve the temp user's id"

# --- 5. password-grant a "kiban-api"-audienced token ---
# Mint through the gateway's OWN `/auth/*` proxy (TLS, self-signed dev cert -> -k), not
# Keycloak's directly-published host port — see infra/compose.yaml's KEYCLOAK_ISSUER_URL comment:
# a real login and this script's own password-grant token must carry the SAME issuer, since both
# are checked against the gateway-origin issuer.
log "minting a token via the password grant"
token_response="$(curl -sfk -X POST "$gw_base/auth/realms/$KEYCLOAK_REALM/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=$smoke_client_id" \
  -d "client_secret=$smoke_client_secret" \
  -d "username=$smoke_username" \
  -d "password=$smoke_password" \
  -d "scope=openid")"
access_token="$(echo "$token_response" | jq -r '.access_token // empty')"
[ -n "$access_token" ] || fail "password grant did not return an access_token: $token_response"

# base64 -d on an unpadded base64url segment (standard JWT shape) reports a non-zero exit even
# though it decodes enough to produce valid, complete JSON (the padding warning is about
# trailing bytes past the closing brace) — wrapped in a subshell that always exits 0 so
# `set -o pipefail` above doesn't treat that as this whole line's failure.
aud="$(echo "$access_token" | cut -d. -f2 | tr '_-' '/+' | (base64 -d 2>/dev/null; true) | jq -r '.aud')"
log "token audience: $aud"
case "$aud" in
*kiban-api*) : ;;
*) fail "token audience does not include kiban-api: $aud" ;;
esac

# --- 6. the actual proof: GET .../api/platform/capabilities through the gateway ---
log "GET $gw_base/api/platform/capabilities through the gateway"
http_code="$(curl -sk -o /tmp/e2e-smoke-body.json -w '%{http_code}' \
  "$gw_base/api/platform/capabilities" \
  -H "Authorization: Bearer $access_token")"
body="$(cat /tmp/e2e-smoke-body.json)"

if [ "$http_code" != "200" ]; then
  fail "capabilities call returned $http_code, want 200 (body: $body)"
fi
if ! echo "$body" | jq -e 'has("data")' >/dev/null 2>&1; then
  fail "200 response has no \"data\" envelope: $body"
fi

log "PASS: token -> gateway -> /api/platform/capabilities -> 200 {\"data\": ...}"
log "body: $body"
