#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Notification worker restart-survival proof. Enqueues real EMAIL deliveries
# through the gateway's own API (a fixture channel/subscription/message, same pattern as
# curl-proof.sh) to mailpit (`--profile test`), kills the `kiban-test-notification-1` CONTAINER
# (not just the process — a hard `docker kill`, catching a job genuinely mid-lease per
# worker.go's own header comment: "stopping it ... mid-lease, with no complete/fail ever
# recorded, is exactly the 'kill worker mid-lease' scenario the mandatory test drives"),
# restarts it, and asserts every job eventually reaches `status='done'` (leases resumed —
# claim_group scoping means this test must target the CONTAINER's OWN claim group,
# which is the production default `"default"` (modules/notification/service/cmd/main.go's
# `KIBAN_NOTIFICATION_CLAIM_GROUP` default) — this script never sets a custom claim_group, so
# messages sent through the real gateway API land in the exact group the restarted container's
# own worker claims from).
#
# Email, not webhook: webhook delivery was tried first and abandoned — `webhook_policy.go`'s SSRF
# guard (`isDisallowedWebhookAddr`) unconditionally rejects loopback/private/link-local resolved
# addresses with NO override (unlike the scheme rule's `KIBAN_WEBHOOK_ALLOW_HTTP` dev opt-in),
# and EVERY reachable target in this compose network (the `webhook-target` container's own
# bridge-network IP, or the host loopback the published port sits behind) resolves to a private
# address — `webhook_test.go`'s own `TestWebhookSender_BuildWebhookRequest_...` header comment
# already documents this exact limitation ("the default WebhookPolicy always rejects loopback/
# private addresses, so a real httptest.Server can't be reached this way without weakening the
# SSRF guard"). Weakening that guard even for kiban-test is not acceptable: SSRF protection is a
# security control. Email has no equivalent guard
# (net/smtp dials `KIBAN_NOTIFICATION_SMTP_HOST` directly, mailpit here) and goes through the
# SAME leased `delivery_job`/worker machinery as webhook — kind='email' vs 'webhook' only changes
# which `Deliverer` the worker calls (worker.go's `Store`/`Mailer`/`Webhook` fields), not the
# claim/lease/complete/fail loop this proof is actually exercising.
#
# Delivery honesty: the module contract's delivery semantics (and mailer.go's own Message-Id
# comment) are explicit that this platform's guarantee is AT-LEAST-ONCE, never exactly-once — a
# job killed mid-SMTP-dial may have already reached the receiver before the process died, and the
# SAME job (same id, same Message-Id) is retried after the lease expires. This script does NOT
# claim zero-duplicate-deliveries (that would misrepresent the system); it asserts the two things
# that ARE the real restart-survival guarantee: (1) no job is ever LOST (every enqueued job
# reaches 'done'), and (2) every delivery mailpit received for a given job carries THAT job's own
# stable Message-Id, proving a receiver-side dedupe by that header is actually possible — i.e.
# any duplicate is a same-id redelivery, never a missing or mismatched one.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
cd "$repo_root"

log() { echo "[restart-survival] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

# shellcheck disable=SC1091
. infra/proof-env.sh
proof_env .env.test

kc_base="http://127.0.0.1:${KEYCLOAK_HOST_PORT}"
gw_base="https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT}"
realm_url="$kc_base/admin/realms/$KEYCLOAK_REALM"
container="kiban-test-notification-1"

psql_c() {
  PGPASSWORD="$KIBAN_DB_PASSWORD" psql -h 127.0.0.1 -p "$POSTGRES_HOST_PORT" -U kiban -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tAc "$1"
}

docker inspect "$container" >/dev/null 2>&1 || fail "container '$container' not found — is the kiban-test stack up (make test-stack-up)?"
docker inspect kiban-test-mailpit-1 >/dev/null 2>&1 || fail "container 'kiban-test-mailpit-1' not found — bring it up: docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml -f infra/compose.test.yaml --project-directory infra --profile test up -d mailpit"
mailpit_base="http://127.0.0.1:8025"

log "fetching a Keycloak master admin token"
admin_token="$(curl -sf -X POST "$kc_base/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=$KC_BOOTSTRAP_ADMIN_USERNAME" -d "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" \
  | jq -r '.access_token')"
[ -n "$admin_token" ] && [ "$admin_token" != "null" ] || fail "could not obtain a Keycloak admin token"
admin_curl() { curl -sf -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" "$@"; }

login_client_id="kiban-e2e-notification-restart-proof"
login_client_secret="restart-proof-$(openssl rand -hex 16)"
existing_client_uuid="$(admin_curl "$realm_url/clients?clientId=$login_client_id" | jq -r '.[0].id // empty')"
client_body="$(jq -n --arg id "$login_client_id" --arg secret "$login_client_secret" '{
  clientId: $id, enabled: true, protocol: "openid-connect",
  publicClient: false, secret: $secret,
  standardFlowEnabled: false, implicitFlowEnabled: false,
  directAccessGrantsEnabled: true, serviceAccountsEnabled: false
}')"
if [ -z "$existing_client_uuid" ]; then
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
superadmin_login_password="restart-proof-superadmin-$(openssl rand -hex 12)"
admin_curl -X PUT "$realm_url/users/$superadmin_id" -d '{"requiredActions": []}' >/dev/null
admin_curl -X PUT "$realm_url/users/$superadmin_id/reset-password" \
  -d "$(jq -n --arg pw "$superadmin_login_password" '{type:"password", value:$pw, temporary:false}')" >/dev/null

log "password-grant login as the seeded superadmin"
token="$(password_grant "$KIBAN_SUPERADMIN_USERNAME" "$superadmin_login_password")"
[ -n "$token" ] || fail "superadmin password-grant login failed"

superadmin_email="$(admin_curl "$realm_url/users/$superadmin_id" | jq -r '.email // empty')"
psql_c "
  INSERT INTO identity.user_account (kc_sub, email, preferred_username)
  VALUES ('$superadmin_id', $( [ -n "$superadmin_email" ] && echo "'$superadmin_email'" || echo NULL ), '$KIBAN_SUPERADMIN_USERNAME')
  ON CONFLICT (kc_sub) DO UPDATE SET preferred_username = EXCLUDED.preferred_username, updated_at = now()" >/dev/null
user_row_id="$(psql_c "SELECT id FROM identity.user_account WHERE kc_sub = '$superadmin_id'")"
[ -n "$user_row_id" ] || fail "no identity.user_account row for the superadmin's kc_sub"
# The platform role's ONLY record is the authz tuple `system:platform#superadmin @ user:<kcSub>`
# (with its grant-ledger and audit rows, written only when the tuple is actually inserted).
psql_c "
  WITH ins AS (
    INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
    VALUES ('system', 'platform', 'superadmin', 'user', '$superadmin_id', '')
    ON CONFLICT DO NOTHING RETURNING subject_id
  ), ledger AS (
    INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
    SELECT 'restart-proof-fixture', 'system', 'platform', 'superadmin', 'user', subject_id, '', 'grant', 'restart-proof-convergence' FROM ins
  )
  INSERT INTO audit.authz__events (actor, action, subject, payload)
  SELECT 'restart-proof-fixture', 'authz.platform_role.grant', 'user:' || subject_id, '{\"role\":\"kiban-superadmin\",\"grantedBy\":\"restart-proof-fixture\",\"seed\":\"restart-proof-convergence\"}'::jsonb
  FROM ins" >/dev/null

log "seeding a test company + a member linking it to the superadmin"
company_id="$(psql_c "
  INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
  VALUES ('company', NULL, 'RESTARTPRF', 'Restart Survival Proof Co', true)
  ON CONFLICT (code) WHERE parent_id IS NULL DO UPDATE SET name = EXCLUDED.name
  RETURNING id" | head -n1)"
[ -n "$company_id" ] || company_id="$(psql_c "SELECT id FROM org.org_unit WHERE code = 'RESTARTPRF' AND parent_id IS NULL")"
psql_c "
  INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
  VALUES ('$company_id', 'SUPERADMIN', 'Superadmin', '$user_row_id', true)
  ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true" >/dev/null
psql_c "
  INSERT INTO authz.default_grant (company_id, module_key, actor)
  VALUES ('$company_id', 'notification', 'restart-proof-fixture')
  ON CONFLICT (company_id, module_key) DO NOTHING" >/dev/null
psql_c "
  INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
  VALUES ('company_module', '$company_id/notification', 'system', 'system', 'platform')
  ON CONFLICT DO NOTHING" >/dev/null
log "company_id=$company_id"

base="$gw_base/api/notification/v1/companies/$company_id"
auth=(-H "Authorization: Bearer $token")

log "POST $base/channels (create email channel)"
run_id="$(date +%s)-$$"
create_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/channels" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg key "restart-proof-chan-$run_id" '{key: $key, label: "Restart Survival Proof", kind: "email"}')")"
create_status="$(echo "$create_out" | tail -n1)"
create_body="$(echo "$create_out" | sed '$d')"
[ "$create_status" = "201" ] || fail "create email channel: expected 201, got $create_status: $create_body"
channel_id="$(echo "$create_body" | jq -r '.data.id')"
log "PASS: create email channel -> 201, channel_id=$channel_id"

recipient_email="restart-proof-$run_id@kiban.local"
log "POST $base/channels/$channel_id/subscriptions (subscribe self with an email address)"
sub_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/channels/$channel_id/subscriptions" "${auth[@]}" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg email "$recipient_email" '{email: $email}')")"
sub_status="$(echo "$sub_out" | tail -n1)"
sub_body="$(echo "$sub_out" | sed '$d')"
[ "$sub_status" = "201" ] || fail "subscribe: expected 201, got $sub_status: $sub_body"
log "PASS: subscribe -> 201, recipient_email=$recipient_email"

# Each message fans out to every non-muted subscriber (modules/notification/service/store.go's
# SendMessage): one recipient here means one delivery_job per message. Send several messages so
# more than one job is in flight when the container gets killed.
job_count=5
log "sending $job_count messages (each enqueues one email delivery_job)"
message_ids=()
for i in $(seq 1 "$job_count"); do
  send_out="$(curl -sk -w '\n%{http_code}' -X POST "$base/messages" "${auth[@]}" -H 'Content-Type: application/json' \
    -H "Idempotency-Key: restart-proof-$run_id-$i" \
    -d "$(jq -n --arg subj "Restart proof $run_id #$i" '{channelId: "'"$channel_id"'", subjectLine: $subj, body: "restart survival proof"}')")"
  send_status="$(echo "$send_out" | tail -n1)"
  send_body="$(echo "$send_out" | sed '$d')"
  case "$send_status" in
    201|200) : ;;
    *) fail "send message #$i: expected 201 or 200, got $send_status: $send_body" ;;
  esac
  message_ids+=("$(echo "$send_body" | jq -r '.data.id')")
done
log "PASS: sent $job_count messages"

job_ids_sql="SELECT id FROM notification.delivery_job WHERE message_id = ANY(ARRAY[$(printf "'%s'," "${message_ids[@]}" | sed 's/,$//')]::uuid[]) ORDER BY created_at"
mapfile -t job_ids < <(psql_c "$job_ids_sql")
[ "${#job_ids[@]}" -eq "$job_count" ] || fail "expected $job_count delivery_job rows, found ${#job_ids[@]}"
log "delivery_job ids: ${job_ids[*]}"

# Wait for at least one job to actually be CLAIMED (leased_until set) before killing — this is
# what makes the kill a genuine "mid-lease" scenario (worker.go's own header comment) rather than
# a lucky pre-claim kill that would trivially restart clean.
log "waiting for at least one job to be claimed (leased_until set) before killing the container"
claimed_deadline=$((SECONDS + 15))
claimed_count=0
while [ "$SECONDS" -lt "$claimed_deadline" ]; do
  claimed_count="$(psql_c "SELECT count(*) FROM notification.delivery_job WHERE id = ANY(ARRAY[$(printf "'%s'," "${job_ids[@]}" | sed 's/,$//')]::uuid[]) AND leased_until IS NOT NULL")"
  [ "$claimed_count" -gt 0 ] && break
done
[ "$claimed_count" -gt 0 ] || fail "no job was claimed within 15s — worker may not be polling (is the notification container healthy?)"
log "PASS: $claimed_count/$job_count job(s) claimed — killing the container now (docker kill, hard stop, no graceful shutdown)"

docker kill "$container" >/dev/null
log "killed $container"
sleep 1
docker start "$container" >/dev/null
log "restarted $container"

# Wait for the container to be healthy again before polling for completion.
health_deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$health_deadline" ]; do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "unknown")"
  [ "$status" = "healthy" ] && break
done
[ "$status" = "healthy" ] || fail "container did not become healthy again within 30s after restart (last status: $status)"
log "PASS: container healthy again after restart"

# The killed job's lease (30s, worker.go's Worker.LeaseDuration) must fully expire before the
# restarted worker (or any worker) can reclaim it (ClaimJobs' own WHERE clause: leased_until IS
# NULL OR leased_until < now()) — this wait is the actual restart-survival mechanism, not a test
# artifact: the leased-jobs design deliberately does NOT let a fresh worker steal a lease
# that hasn't expired yet, even from a process that's provably dead.
log "waiting up to 60s for all $job_count jobs to reach status='done' (the killed job's lease must expire before it's reclaimable)"
done_deadline=$((SECONDS + 60))
done_count=0
while [ "$SECONDS" -lt "$done_deadline" ]; do
  done_count="$(psql_c "SELECT count(*) FROM notification.delivery_job WHERE id = ANY(ARRAY[$(printf "'%s'," "${job_ids[@]}" | sed 's/,$//')]::uuid[]) AND status = 'done'")"
  [ "$done_count" -eq "$job_count" ] && break
  sleep 2
done
[ "$done_count" -eq "$job_count" ] || {
  psql_c "SELECT id, status, attempts, leased_until, last_error FROM notification.delivery_job WHERE id = ANY(ARRAY[$(printf "'%s'," "${job_ids[@]}" | sed 's/,$//')]::uuid[])"
  fail "expected all $job_count jobs 'done' within 60s of restart, got $done_count — no job may be lost after a mid-lease kill"
}
log "PASS: all $job_count jobs reached 'done' after restart — no job was lost"

# Message-Id correctness at the receiver: mailpit's own search API (GET /api/v1/search,
# query "to:<addr>") lists every message it has received for this run's recipient — each must
# carry its OWN job's stable Message-Id (mailer.go: "<jobId>@kiban.notification"), and every job
# must have been seen AT LEAST once (at-least-once, the module contract's documented guarantee —
# a duplicate same-id delivery from the mid-lease kill is expected and fine, a missing or
# mismatched one is not).
log "checking mailpit for Message-Id correctness"
mailpit_results="$(curl -sf "$mailpit_base/api/v1/search?query=$(printf '%s' "to:$recipient_email" | jq -sRr @uri)" | jq -r '.messages[].ID')"
missing=0
for job_id in "${job_ids[@]}"; do
  seen_count=0
  for mp_id in $mailpit_results; do
    msg_id_header="$(curl -sf "$mailpit_base/api/v1/message/$mp_id" | jq -r '.MessageID // empty')"
    if [ "$msg_id_header" = "${job_id}@kiban.notification" ]; then
      seen_count=$((seen_count + 1))
    fi
  done
  if [ "$seen_count" -eq 0 ]; then
    log "job $job_id: NEVER seen at mailpit"
    missing=$((missing + 1))
  else
    log "job $job_id: seen $seen_count time(s) at mailpit (>=1 is correct per the at-least-once contract; >1 is an expected same-id redelivery from the mid-lease kill, not a bug)"
  fi
done
[ "$missing" -eq 0 ] || fail "$missing/$job_count job(s) never reached mailpit despite reaching status='done' in the DB"
log "PASS: every job reached mailpit at least once, each under its own stable Message-Id"

log "ALL CHECKS PASSED"
