#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Curl proof for the helpdesk module (same fixture shape and final disable-module-then-403
# capability proof as modules/notification/curl-proof.sh). This script targets
# ONLY the isolated `kiban-test` project (.env.test, ports 15434/18081/18543/18100), never
# .env's `kiban` project (public/dev, ports 5434/8081/8443/8090). Exercises the module's
# core API path through the gateway: raise a ticket, list it, read it, comment on it, assign it
# to a second fixture member (auto-granting them agent tier), transition its status, read its
# audit trail, then prove the disabled-module 403.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
cd "$repo_root"

log() { echo "[curl-proof] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

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

login_client_id="kiban-e2e-helpdesk-proof"
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

# Converge the identity.user_account row + superadmin tuple for the seeded superadmin on kiban-test (may not
# exist yet — `make check`'s dbtest truncation wipes them; mirrors
# web/shell/e2e/global-setup.ts's convergeSuperadminIdentity / internal/bootstrap's SuperadminStep).
superadmin_email="$(admin_curl "$realm_url/users/$superadmin_id" | jq -r '.email // empty')"
psql_c "
  INSERT INTO identity.user_account (kc_sub, email, preferred_username)
  VALUES ('$superadmin_id', $( [ -n "$superadmin_email" ] && echo "'$superadmin_email'" || echo NULL ), '$KIBAN_SUPERADMIN_USERNAME')
  ON CONFLICT (kc_sub) DO UPDATE SET preferred_username = EXCLUDED.preferred_username, updated_at = now()" >/dev/null
# Converge the superadmin's identity row (the same fixture the e2e harness uses): the gateway
# provisions it on the first request from an unseen subject, but a test run may have truncated
# the table after the gateway cached this subject as provisioned.
user_row_id="$(psql_c "
  INSERT INTO identity.user_account (kc_sub, preferred_username)
  VALUES ('$superadmin_id', '$KIBAN_SUPERADMIN_USERNAME')
  ON CONFLICT (kc_sub) DO UPDATE SET updated_at = now()
  RETURNING id" | head -n1)"
[ -n "$user_row_id" ] || fail "could not converge the superadmin's identity.user_account row"
# The platform role's ONLY record is the authz tuple `system:platform#superadmin @ user:<kcSub>`
# (with its grant-ledger and audit rows, written only when the tuple is actually inserted).
psql_c "
  WITH ins AS (
    INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
    VALUES ('system', 'platform', 'superadmin', 'user', '$superadmin_id', '')
    ON CONFLICT DO NOTHING RETURNING subject_id
  ), ledger AS (
    INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
    SELECT 'curl-proof-fixture', 'system', 'platform', 'superadmin', 'user', subject_id, '', 'grant', 'curl-proof-convergence' FROM ins
  )
  INSERT INTO audit.authz__events (actor, action, subject, payload)
  SELECT 'curl-proof-fixture', 'authz.platform_role.grant', 'user:' || subject_id, '{\"role\":\"kiban-superadmin\",\"grantedBy\":\"curl-proof-fixture\",\"seed\":\"curl-proof-convergence\"}'::jsonb
  FROM ins" >/dev/null

log "seeding a test company + a member linking it to the superadmin, plus a second (linked) member to assign as agent (test fixture, direct DB — org has no gateway-mounted company/member-create route yet)"
company_id="$(psql_c "
  INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
  VALUES ('company', NULL, 'HDPRF', 'Helpdesk Curl Proof Co', true)
  ON CONFLICT (code) WHERE parent_id IS NULL DO UPDATE SET name = EXCLUDED.name
  RETURNING id" | head -n1)"
[ -n "$company_id" ] || company_id="$(psql_c "SELECT id FROM org.org_unit WHERE code = 'HDPRF' AND parent_id IS NULL")"
psql_c "
  INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
  VALUES ('$company_id', 'SUPERADMIN', 'Superadmin', '$user_row_id', true)
  ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true" >/dev/null
agent_kc_sub="$(psql_c "SELECT gen_random_uuid()")"
agent_user_row_id="$(psql_c "
  INSERT INTO identity.user_account (kc_sub, email, preferred_username)
  VALUES ('$agent_kc_sub', 'curl-proof-agent@kiban.local', 'curl-proof-agent')
  ON CONFLICT (kc_sub) DO UPDATE SET updated_at = now()
  RETURNING id" | head -n1)"
agent_member_id="$(psql_c "
  INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
  VALUES ('$company_id', 'AGENT', 'Curl Proof Agent', '$agent_user_row_id', true)
  ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
  RETURNING id" | head -n1)"
[ -n "$agent_member_id" ] || agent_member_id="$(psql_c "SELECT id FROM org.member WHERE company_id = '$company_id' AND code = 'AGENT'")"
# The default module-access grant is written by production hooks that this direct-SQL
# fixture company never triggers — mirror authz/store.EnsureDefaultGrant's two writes here, same
# posture as modules/notification/curl-proof.sh's own equivalent block.
psql_c "
  INSERT INTO authz.default_grant (company_id, module_key, actor)
  VALUES ('$company_id', 'helpdesk', 'curl-proof-fixture')
  ON CONFLICT (company_id, module_key) DO NOTHING" >/dev/null
psql_c "
  INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('company_module', '$company_id/helpdesk', 'system', 'system', 'platform')
  ON CONFLICT DO NOTHING" >/dev/null
log "company_id=$company_id agent_member_id=$agent_member_id"

base="$gw_base/api/helpdesk/v1/companies/$company_id"
auth=(-H "Authorization: Bearer $token")

log "POST $base/tickets (raise)"
create_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/tickets" "${auth[@]}" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: curl-proof-helpdesk-1' \
  -d '{"title":"Curl Proof Ticket","description":"Initial description"}')"
create_status="$(echo "$create_out" | tail -n1)"
create_body="$(echo "$create_out" | sed '$d')"
case "$create_status" in
  201|200) : ;;
  *) fail "create ticket: expected 201 or 200, got $create_status: $create_body" ;;
esac
ticket_id="$(echo "$create_body" | jq -r '.data.id')"
log "PASS: create ticket -> $create_status, ticket_id=$ticket_id"

log "GET $base/tickets?view=all (list)"
list_out="$(curl -sk -w '\n%{http_code}' "$base/tickets?view=all" "${auth[@]}")"
list_status="$(echo "$list_out" | tail -n1)"
list_body="$(echo "$list_out" | sed '$d')"
[ "$list_status" = "200" ] || fail "list tickets: expected 200, got $list_status: $list_body"
echo "$list_body" | jq -e --arg id "$ticket_id" '.data[] | select(.id == $id)' >/dev/null \
  || fail "list tickets: created ticket not found in list: $list_body"
log "PASS: list tickets -> 200, created ticket present"

log "GET $base/tickets/$ticket_id (read)"
get_status="$(curl -sk -o /tmp/curl-proof-helpdesk-get.json -w '%{http_code}' "$base/tickets/$ticket_id" "${auth[@]}")"
[ "$get_status" = "200" ] || fail "get ticket: expected 200, got $get_status: $(cat /tmp/curl-proof-helpdesk-get.json)"
log "PASS: get ticket -> 200"

log "POST $base/tickets/$ticket_id/comments (comment)"
comment_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/tickets/$ticket_id/comments" "${auth[@]}" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: curl-proof-helpdesk-comment-1' \
  -d '{"body":"A curl-proof comment"}')"
comment_status="$(echo "$comment_out" | tail -n1)"
comment_body="$(echo "$comment_out" | sed '$d')"
case "$comment_status" in
  201|200) : ;;
  *) fail "create comment: expected 201 or 200, got $comment_status: $comment_body" ;;
esac
log "PASS: create comment -> $comment_status"

log "POST $base/tickets/$ticket_id/assign (assign to second member, auto-grants agent tier)"
assign_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/tickets/$ticket_id/assign" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg mid "$agent_member_id" '{assigneeMemberId: $mid}')")"
assign_status="$(echo "$assign_out" | tail -n1)"
assign_body="$(echo "$assign_out" | sed '$d')"
[ "$assign_status" = "200" ] || fail "assign ticket: expected 200, got $assign_status: $assign_body"
echo "$assign_body" | jq -e --arg mid "$agent_member_id" '.data.assigneeMemberId == $mid' >/dev/null || fail "assign ticket: assigneeMemberId not set"
log "PASS: assign ticket -> 200"

log "POST $base/tickets/$ticket_id/status (transition to in_progress)"
status_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/tickets/$ticket_id/status" "${auth[@]}" -H 'Content-Type: application/json' \
  -d '{"status":"in_progress"}')"
status_status="$(echo "$status_out" | tail -n1)"
status_body="$(echo "$status_out" | sed '$d')"
[ "$status_status" = "200" ] || fail "transition status: expected 200, got $status_status: $status_body"
echo "$status_body" | jq -e '.data.status == "in_progress"' >/dev/null || fail "transition status: status not updated"
log "PASS: transition status -> 200, now in_progress"

log "GET $base/tickets/$ticket_id/audit (audit trail)"
audit_status="$(curl -sk -o /tmp/curl-proof-helpdesk-audit.json -w '%{http_code}' "$base/tickets/$ticket_id/audit" "${auth[@]}")"
[ "$audit_status" = "200" ] || fail "get audit: expected 200, got $audit_status: $(cat /tmp/curl-proof-helpdesk-audit.json)"
cat /tmp/curl-proof-helpdesk-audit.json | jq -e '.data | length > 0' >/dev/null || fail "get audit: empty audit trail"
log "PASS: get audit -> 200, non-empty"

log "POST /api/platform/admin/modules/helpdesk/disable (superadmin)"
disable_status="$(curl -sk -o /tmp/curl-proof-helpdesk-disable.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/helpdesk/disable" "${auth[@]}")"
[ "$disable_status" = "200" ] || fail "disable module: expected 200, got $disable_status: $(cat /tmp/curl-proof-helpdesk-disable.json)"
log "PASS: disable module -> 200"

log "GET $base/tickets while disabled (expect 403 MODULE_DISABLED)"
sleep 6 # catalog.go's snapshot TTL is 5s — wait it out so the gateway re-fetches
cap_out="$(curl -sk -w '\n%{http_code}' "$base/tickets" "${auth[@]}")"
cap_status="$(echo "$cap_out" | tail -n1)"
cap_body="$(echo "$cap_out" | sed '$d')"
[ "$cap_status" = "403" ] || fail "disabled-module capability check: expected 403, got $cap_status: $cap_body"
echo "$cap_body" | jq -e '.error.code == "MODULE_DISABLED"' >/dev/null || fail "expected error.code MODULE_DISABLED, got $cap_body"
log "PASS: disabled module -> 403 MODULE_DISABLED"

log "POST /api/platform/admin/modules/helpdesk/enable (restore for future runs)"
curl -sk -o /dev/null -X POST "$gw_base/api/platform/admin/modules/helpdesk/enable" "${auth[@]}"

log "ALL CHECKS PASSED"
