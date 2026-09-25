#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Curl proof for the timesheet module, mirroring modules/notification/curl-proof.sh's
# fixture/proof shape (client/superadmin/company/default-grant setup, disable-module-then-403
# capability proof at the end) — but this script targets
# ONLY the isolated `kiban-test` project (.env.test, ports 15434/18081/18543/18100), never
# .env's `kiban` project (public/dev, ports 5434/8081/8443/8090). Exercises the module's
# core API path through the gateway: create a project, assign a second fixture member as their
# own approver (grants submitter+approver relations), upsert a draft entry against the project,
# submit the week, approve the submission, then prove the disabled-module 403. The superadmin
# acts as BOTH the submitter (via the assign-approver step below, which grants ITSELF submitter
# too — see the assign-approver call) and the approver, since a single logged-in identity is
# simplest for a fixture proof (the shell e2e suite's timesheet.spec.ts covers the two-identity
# submitter/approver journey through the real browser).
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

login_client_id="kiban-e2e-timesheet-proof"
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

log "seeding a test company + a member linking it to the superadmin (test fixture, direct DB — org has no gateway-mounted company/member-create route yet)"
company_id="$(psql_c "
  INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
  VALUES ('company', NULL, 'TSPRF', 'Timesheet Curl Proof Co', true)
  ON CONFLICT (code) WHERE parent_id IS NULL DO UPDATE SET name = EXCLUDED.name
  RETURNING id" | head -n1)"
[ -n "$company_id" ] || company_id="$(psql_c "SELECT id FROM org.org_unit WHERE code = 'TSPRF' AND parent_id IS NULL")"
member_id="$(psql_c "
  INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
  VALUES ('$company_id', 'SUPERADMIN', 'Superadmin', '$user_row_id', true)
  ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
  RETURNING id" | head -n1)"
[ -n "$member_id" ] || member_id="$(psql_c "SELECT id FROM org.member WHERE company_id = '$company_id' AND code = 'SUPERADMIN'")"
# The default module-access grant is written by production hooks that this direct-SQL
# fixture company never triggers — mirror authz/store.EnsureDefaultGrant's two writes here, same
# posture as modules/notification/curl-proof.sh's own equivalent block.
psql_c "
  INSERT INTO authz.default_grant (company_id, module_key, actor)
  VALUES ('$company_id', 'timesheet', 'curl-proof-fixture')
  ON CONFLICT (company_id, module_key) DO NOTHING" >/dev/null
psql_c "
  INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('company_module', '$company_id/timesheet', 'system', 'system', 'platform')
  ON CONFLICT DO NOTHING" >/dev/null
log "company_id=$company_id member_id=$member_id"

base="$gw_base/api/timesheet/v1/companies/$company_id"
auth=(-H "Authorization: Bearer $token")

log "POST $base/projects (create)"
proj_code="CPRF$(date +%s | tail -c 6)"
proj_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/projects" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg code "$proj_code" '{code: $code, name: "Curl Proof Project", status: "active"}')")"
proj_status="$(echo "$proj_out" | tail -n1)"
proj_body="$(echo "$proj_out" | sed '$d')"
[ "$proj_status" = "201" ] || fail "create project: expected 201, got $proj_status: $proj_body"
project_id="$(echo "$proj_body" | jq -r '.data.id')"
log "PASS: create project -> 201, project_id=$project_id"

log "GET $base/projects (list)"
list_status="$(curl -sk -o /tmp/curl-proof-timesheet-list.json -w '%{http_code}' "$base/projects" "${auth[@]}")"
[ "$list_status" = "200" ] || fail "list projects: expected 200, got $list_status: $(cat /tmp/curl-proof-timesheet-list.json)"
cat /tmp/curl-proof-timesheet-list.json | jq -e --arg id "$project_id" '.data.items[] | select(.id == $id)' >/dev/null \
  || fail "list projects: created project not found: $(cat /tmp/curl-proof-timesheet-list.json)"
log "PASS: list projects -> 200, created project present"

log "POST $base/approvers (assign self as own approver — grants submitter+approver relations)"
approver_status="$(curl -sk -o /tmp/curl-proof-timesheet-approver.json -w '%{http_code}' -X POST "$base/approvers" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg mid "$member_id" '{memberId: $mid, approverMemberId: $mid}')")"
[ "$approver_status" = "200" ] || fail "assign approver: expected 200, got $approver_status: $(cat /tmp/curl-proof-timesheet-approver.json)"
log "PASS: assign approver -> 200"

# Monday of a week guaranteed to be within Config's allowedPreviousWeeks/allowedFutureWeeks
# window relative to "today" — this run's current ISO week Monday.
week_start="$(date -u -d "$(date -u +%Y-%m-%d) -$(( $(date -u +%u) - 1 )) days" +%Y-%m-%d)"
entry_date="$week_start"

log "POST $base/entries (upsert draft entry for $entry_date)"
entry_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/entries" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg pid "$project_id" --arg date "$entry_date" '{projectId: $pid, entryDate: $date, realHours: 4, billableHours: 4}')")"
entry_status="$(echo "$entry_out" | tail -n1)"
entry_body="$(echo "$entry_out" | sed '$d')"
[ "$entry_status" = "200" ] || fail "upsert entry: expected 200, got $entry_status: $entry_body"
log "PASS: upsert entry -> 200"

log "GET $base/entries?weekStart=$week_start (list week entries)"
week_status="$(curl -sk -o /tmp/curl-proof-timesheet-entries.json -w '%{http_code}' "$base/entries?weekStart=$week_start" "${auth[@]}")"
[ "$week_status" = "200" ] || fail "list week entries: expected 200, got $week_status: $(cat /tmp/curl-proof-timesheet-entries.json)"
log "PASS: list week entries -> 200"

log "POST $base/submissions (submit week)"
submit_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/submissions" "${auth[@]}" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: curl-proof-timesheet-1' \
  -d "$(jq -n --arg ws "$week_start" '{weekStart: $ws}')")"
submit_status="$(echo "$submit_out" | tail -n1)"
submit_body="$(echo "$submit_out" | sed '$d')"
case "$submit_status" in
  201|200) : ;;
  *) fail "submit week: expected 201 or 200, got $submit_status: $submit_body" ;;
esac
submission_id="$(echo "$submit_body" | jq -r '.data.id')"
log "PASS: submit week -> $submit_status, submission_id=$submission_id"

log "GET $base/submissions?view=mine (list)"
subs_status="$(curl -sk -o /tmp/curl-proof-timesheet-subs.json -w '%{http_code}' "$base/submissions?view=mine" "${auth[@]}")"
[ "$subs_status" = "200" ] || fail "list submissions: expected 200, got $subs_status: $(cat /tmp/curl-proof-timesheet-subs.json)"
log "PASS: list submissions -> 200"

log "POST $base/submissions/$submission_id/approve"
approve_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/submissions/$submission_id/approve" "${auth[@]}")"
approve_status="$(echo "$approve_out" | tail -n1)"
approve_body="$(echo "$approve_out" | sed '$d')"
case "$approve_status" in
  200) : ;;
  422)
    # A prior run of this script may have already approved this exact submission (same
    # weekStart, so `submitWeek`'s idempotency-key replay above returned the ORIGINAL
    # already-approved submission) — an approve-already-approved 422 is a pass in that case, not
    # a failure, same idempotent-rerun posture as notification's own curl-proof.sh.
    log "PASS (idempotent re-run): submission already approved (422: $approve_body)"
    ;;
  *) fail "approve submission: expected 200 or 422 (already approved), got $approve_status: $approve_body" ;;
esac
[ "$approve_status" != "200" ] || { echo "$approve_body" | jq -e '.data.status == "approved"' >/dev/null || fail "approve submission: status not approved"; log "PASS: approve submission -> 200, now approved"; }

log "POST /api/platform/admin/modules/timesheet/disable (superadmin)"
disable_status="$(curl -sk -o /tmp/curl-proof-timesheet-disable.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/timesheet/disable" "${auth[@]}")"
[ "$disable_status" = "200" ] || fail "disable module: expected 200, got $disable_status: $(cat /tmp/curl-proof-timesheet-disable.json)"
log "PASS: disable module -> 200"

log "GET $base/projects while disabled (expect 403 MODULE_DISABLED)"
sleep 6 # catalog.go's snapshot TTL is 5s — wait it out so the gateway re-fetches
cap_out="$(curl -sk -w '\n%{http_code}' "$base/projects" "${auth[@]}")"
cap_status="$(echo "$cap_out" | tail -n1)"
cap_body="$(echo "$cap_out" | sed '$d')"
[ "$cap_status" = "403" ] || fail "disabled-module capability check: expected 403, got $cap_status: $cap_body"
echo "$cap_body" | jq -e '.error.code == "MODULE_DISABLED"' >/dev/null || fail "expected error.code MODULE_DISABLED, got $cap_body"
log "PASS: disabled module -> 403 MODULE_DISABLED"

log "POST /api/platform/admin/modules/timesheet/enable (restore for future runs)"
curl -sk -o /dev/null -X POST "$gw_base/api/platform/admin/modules/timesheet/enable" "${auth[@]}"

log "ALL CHECKS PASSED"
