#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Headless curl proof: send -> poll inbox -> mark read, through the gateway (TLS edge), plus the
# capability-403-when-disabled proof. Reuses infra/e2e-login.sh's superadmin password-grant
# pattern. Test-fixture setup (a company + a linked member) is done directly against Postgres,
# same as e2e-login.sh's own fake-module-row fixture — org has no company/member-create route
# mounted at the gateway, so this is fixture plumbing, not something the notification module
# itself needs.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
cd "$repo_root"

log() { echo "[curl-proof] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

# This script targets ONLY the isolated `kiban-test` project (.env.test, ports
# 15434/18081/18543/18100; web/e2e-shared/env.ts's loadTestEnv is the TypeScript equivalent),
# never .env's `kiban` project (public/dev, ports 5434/8081/8443/8090) — the same posture
# as the docs/helpdesk/timesheet proofs.
# shellcheck disable=SC1091
. infra/proof-env.sh
proof_env .env.test

kc_base="http://127.0.0.1:${KEYCLOAK_HOST_PORT}"
gw_base="https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT}"
realm_url="$kc_base/admin/realms/$KEYCLOAK_REALM"

psql_c() {
  PGPASSWORD="$KIBAN_DB_PASSWORD" psql -h 127.0.0.1 -p "$POSTGRES_HOST_PORT" -U kiban -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tAc "$1"
}

log "fetching a Keycloak master admin token"
admin_token="$(curl -sf -X POST "$kc_base/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=$KC_BOOTSTRAP_ADMIN_USERNAME" -d "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" \
  | jq -r '.access_token')"
[ -n "$admin_token" ] && [ "$admin_token" != "null" ] || fail "could not obtain a Keycloak admin token"
admin_curl() { curl -sf -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" "$@"; }

# A direct-grant-capable client with a "kiban-api" audience mapper (idempotent create-or-reuse,
# same pattern as infra/e2e-login.sh / infra/e2e-smoke.sh: the realm ships no client with both by
# default — every service's TokenVerifier, including notification's own, requires the audience
# to be exactly "kiban-api").
login_client_id="kiban-e2e-notification-proof"
login_client_secret="curl-proof-$(openssl rand -hex 16)"
existing_client_uuid="$(admin_curl "$realm_url/clients?clientId=$login_client_id" | jq -r '.[0].id // empty')"
client_body="$(jq -n --arg id "$login_client_id" --arg secret "$login_client_secret" '{
  clientId: $id, enabled: true, protocol: "openid-connect",
  publicClient: false, secret: $secret,
  standardFlowEnabled: false, implicitFlowEnabled: false,
  directAccessGrantsEnabled: true, serviceAccountsEnabled: false
}')"
if [ -z "$existing_client_uuid" ]; then
  log "creating $login_client_id"
  admin_curl -X POST "$realm_url/clients" -d "$client_body" >/dev/null
  client_uuid="$(admin_curl "$realm_url/clients?clientId=$login_client_id" | jq -r '.[0].id')"
else
  client_uuid="$existing_client_uuid"
  admin_curl -X PUT "$realm_url/clients/$client_uuid" -d "$client_body" >/dev/null
fi
mapper_exists="$(admin_curl "$realm_url/clients/$client_uuid/protocol-mappers/models" | jq -r '[.[] | select(.name=="kiban-api-audience")] | length')"
if [ "$mapper_exists" = "0" ]; then
  admin_curl -X POST "$realm_url/clients/$client_uuid/protocol-mappers/models" -d '{
    "name": "kiban-api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
    "config": {"included.custom.audience": "kiban-api", "access.token.claim": "true", "id.token.claim": "false"}
  }' >/dev/null
fi

password_grant() {
  # Through the gateway's own /auth/* proxy (NOT Keycloak's raw host port) — the token's `iss`
  # claim must be the gateway's public origin, matching every service's KEYCLOAK_ISSUER_URL
  # (see internal/gateway/auth_proxy.go and every cmd/*/main.go's own comment on this).
  curl -sfk -X POST "$gw_base/auth/realms/$KEYCLOAK_REALM/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=$login_client_id" -d "client_secret=$login_client_secret" \
    -d "username=$1" -d "password=$2" -d "scope=openid" | jq -r '.access_token // empty'
}

superadmin_id="$(admin_curl "$realm_url/users?username=$KIBAN_SUPERADMIN_USERNAME&exact=true" | jq -r '.[0].id // empty')"
[ -n "$superadmin_id" ] || fail "seeded superadmin '$KIBAN_SUPERADMIN_USERNAME' not found — did bootstrap run?"
superadmin_login_password="curl-proof-superadmin-$(openssl rand -hex 12)"
admin_curl -X PUT "$realm_url/users/$superadmin_id" -d '{"requiredActions": []}' >/dev/null
admin_curl -X PUT "$realm_url/users/$superadmin_id/reset-password" \
  -d "$(jq -n --arg pw "$superadmin_login_password" '{type:"password", value:$pw, temporary:false}')" >/dev/null

log "password-grant login as the seeded superadmin"
token="$(password_grant "$KIBAN_SUPERADMIN_USERNAME" "$superadmin_login_password")"
[ -n "$token" ] || fail "superadmin password-grant login failed"
log "PASS: superadmin login"

# Converge the superadmin's identity row (the same fixture the e2e harness uses): the gateway
# provisions it on the first request from an unseen subject, but a test run may have truncated
# the table after the gateway cached this subject as provisioned.
user_row_id="$(psql_c "
  INSERT INTO identity.user_account (kc_sub, preferred_username)
  VALUES ('$superadmin_id', '$KIBAN_SUPERADMIN_USERNAME')
  ON CONFLICT (kc_sub) DO UPDATE SET updated_at = now()
  RETURNING id" | head -n1)"
[ -n "$user_row_id" ] || fail "could not converge the superadmin's identity.user_account row"

log "seeding a test company + a member linking it to the superadmin (test fixture, direct DB — org has no gateway-mounted company/member-create route yet)"
company_id="$(psql_c "
  INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
  VALUES ('company', NULL, 'NOTIFPRF', 'Notification Curl Proof Co', true)
  ON CONFLICT (code) WHERE parent_id IS NULL DO UPDATE SET name = EXCLUDED.name
  RETURNING id" | head -n1)"
[ -n "$company_id" ] || company_id="$(psql_c "SELECT id FROM org.org_unit WHERE code = 'NOTIFPRF' AND parent_id IS NULL")"
psql_c "
  INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
  VALUES ('$company_id', 'SUPERADMIN', 'Superadmin', '$user_row_id', true)
  ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true" >/dev/null
# The default module-access grant is written by production hooks (bootstrap converge,
# registry Seed/SetEnabled, org's own company-creation path) — this fixture company is created by
# direct SQL above (same reason as the comment at the top of this file), so none of them fire for
# it. Mirror authz/store.EnsureDefaultGrant's two writes as fixture plumbing, same posture as the
# company/member rows above (never how the real code paths grant this).
psql_c "
  INSERT INTO authz.default_grant (company_id, module_key, actor)
  VALUES ('$company_id', 'notification', 'curl-proof-fixture')
  ON CONFLICT (company_id, module_key) DO NOTHING" >/dev/null
psql_c "
  INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('company_module', '$company_id/notification', 'system', 'system', 'platform')
  ON CONFLICT DO NOTHING" >/dev/null
log "company_id=$company_id"

base="$gw_base/api/notification/v1/companies/$company_id"
auth=(-H "Authorization: Bearer $token")

log "POST $base/channels (create channel)"
create_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/channels" "${auth[@]}" -H 'Content-Type: application/json' \
  -d '{"key":"curl-proof-chan","label":"Curl Proof","kind":"in_app"}')"
create_status="$(echo "$create_out" | tail -n1)"
create_body="$(echo "$create_out" | sed '$d')"
if [ "$create_status" = "201" ]; then
  channel_id="$(echo "$create_body" | jq -r '.data.id')"
  log "PASS: create channel -> 201, channel_id=$channel_id"
elif [ "$create_status" = "409" ]; then
  # Re-run of this script against the same company (key uniqueness is per company+key) — reuse
  # the channel a prior run already created rather than treating this as a failure.
  channel_id="$(curl -sk "$base/channels?pageSize=100" "${auth[@]}" | jq -r '.data.items[] | select(.key=="curl-proof-chan") | .id')"
  [ -n "$channel_id" ] || fail "create channel: got 409 but could not find the existing curl-proof-chan channel"
  log "PASS (idempotent re-run): reusing existing channel_id=$channel_id"
else
  fail "create channel: expected 201 or 409, got $create_status: $create_body"
fi

log "POST $base/channels/$channel_id/subscriptions (subscribe self)"
sub_status="$(curl -sk -o /tmp/curl-proof-sub.json -w '%{http_code}' -X POST "$base/channels/$channel_id/subscriptions" "${auth[@]}")"
[ "$sub_status" = "201" ] || fail "subscribe: expected 201, got $sub_status: $(cat /tmp/curl-proof-sub.json)"
log "PASS: subscribe -> 201"

log "POST $base/messages (send)"
send_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/messages" "${auth[@]}" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: curl-proof-1' \
  -d '{"channelId":"'"$channel_id"'","subjectLine":"Hello from the curl proof","body":"World"}')"
send_status="$(echo "$send_out" | tail -n1)"
send_body="$(echo "$send_out" | sed '$d')"
# 200 = idempotency-key replay from a prior run of this script (SendMessage returns the same
# message, created=false) — both are a pass.
case "$send_status" in
  201|200) : ;;
  *) fail "send message: expected 201 or 200, got $send_status: $send_body" ;;
esac
message_id="$(echo "$send_body" | jq -r '.data.id')"
log "PASS: send message -> $send_status, message_id=$message_id"

log "GET $base/messages (poll inbox)"
inbox_out="$(curl -sk -w '\n%{http_code}' "$base/messages" "${auth[@]}")"
inbox_status="$(echo "$inbox_out" | tail -n1)"
inbox_body="$(echo "$inbox_out" | sed '$d')"
[ "$inbox_status" = "200" ] || fail "poll inbox: expected 200, got $inbox_status: $inbox_body"
echo "$inbox_body" | jq -e --arg id "$message_id" '.data.items[] | select(.id == $id)' >/dev/null \
  || fail "poll inbox: sent message not found in inbox: $inbox_body"
log "PASS: poll inbox -> 200, sent message present"

log "POST $base/messages/$message_id/read (mark read)"
read_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/messages/$message_id/read" "${auth[@]}")"
read_status="$(echo "$read_out" | tail -n1)"
read_body="$(echo "$read_out" | sed '$d')"
[ "$read_status" = "200" ] || fail "mark read: expected 200, got $read_status: $read_body"
echo "$read_body" | jq -e '.data.readAt != null' >/dev/null || fail "mark read: readAt not set: $read_body"
log "PASS: mark read -> 200, readAt set"

log "POST /api/platform/admin/modules/notification/disable (superadmin)"
disable_status="$(curl -sk -o /tmp/curl-proof-disable.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/notification/disable" "${auth[@]}")"
[ "$disable_status" = "200" ] || fail "disable module: expected 200, got $disable_status: $(cat /tmp/curl-proof-disable.json)"
log "PASS: disable module -> 200"

log "GET $base/channels while disabled (expect 403 MODULE_DISABLED)"
sleep 6 # catalog.go's snapshot TTL is 5s — wait it out so the gateway re-fetches
cap_out="$(curl -sk -w '\n%{http_code}' "$base/channels" "${auth[@]}")"
cap_status="$(echo "$cap_out" | tail -n1)"
cap_body="$(echo "$cap_out" | sed '$d')"
[ "$cap_status" = "403" ] || fail "disabled-module capability check: expected 403, got $cap_status: $cap_body"
echo "$cap_body" | jq -e '.error.code == "MODULE_DISABLED"' >/dev/null || fail "expected error.code MODULE_DISABLED, got $cap_body"
log "PASS: disabled module -> 403 MODULE_DISABLED"

log "POST /api/platform/admin/modules/notification/enable (restore for future runs)"
curl -sk -o /dev/null -X POST "$gw_base/api/platform/admin/modules/notification/enable" "${auth[@]}"

log "ALL CHECKS PASSED"
