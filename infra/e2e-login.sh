#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# End-to-end login proof ("the loginable skeleton"):
#
#   make dev-clean && make dev
#   bash infra/e2e-login.sh   # run 1
#   bash infra/e2e-login.sh   # run 2 — must ALSO exit 0 (proves the whole world is idempotent)
#
# Flow: password-grant login as the SEEDED superadmin (created by the bootstrap container, not
# by this script) -> GET /api/platform/capabilities through the TLS gateway (200) -> a
# superadmin mutation (enable a fake/test module row) through the guard (200) -> platform-role
# grant/revoke through the guard (the regular user gains and loses superadmin, effective
# immediately; the last superadmin cannot revoke themselves) -> assert BOTH
# audit rows exist (the authz denial from a negative-case caller in audit.authz__events, the
# registry mutation in audit.registry__events) -> re-run the bootstrap container -> assert it
# converges with zero overwrites of the module we just enabled -> disable the module and prove
# the disabled-module 403 path. Prints a PASS/FAIL summary table; exits 0 only if every check
# passed.
#
# This script does NOT run `make dev-clean && make dev` itself (that's the caller's job) — it
# assumes the stack from `make dev` is already up. Every fixture it creates (Keycloak throwaway
# clients/users, the fake module catalog row) is idempotent create-or-reuse, like
# infra/e2e-smoke.sh, so it can run more than once against the same stack.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

log() { echo "[e2e-login] $*" >&2; }
fail() {
  log "FAIL: $*"
  exit 1
}

declare -a RESULT_NAMES=()
declare -a RESULT_STATUSES=()
record() {
  RESULT_NAMES+=("$1")
  RESULT_STATUSES+=("$2")
}

# --- 0. env — refuses the live stack in PUBLIC mode (infra/proof-env.sh): this script mutates
#        realm/superadmin/fixture state a human may be using. ---
# shellcheck disable=SC1091
. infra/proof-env.sh
proof_env .env

: "${KEYCLOAK_HOST_PORT:?KEYCLOAK_HOST_PORT not set}"
: "${KEYCLOAK_REALM:?KEYCLOAK_REALM not set}"
: "${KC_BOOTSTRAP_ADMIN_USERNAME:?KC_BOOTSTRAP_ADMIN_USERNAME not set}"
: "${KC_BOOTSTRAP_ADMIN_PASSWORD:?KC_BOOTSTRAP_ADMIN_PASSWORD not set}"
: "${POSTGRES_HOST_PORT:?POSTGRES_HOST_PORT not set}"
: "${KIBAN_DB_PASSWORD:?KIBAN_DB_PASSWORD not set}"
: "${POSTGRES_DB:?POSTGRES_DB not set}"
: "${KIBAN_SUPERADMIN_USERNAME:?KIBAN_SUPERADMIN_USERNAME not set}"

kc_base="http://127.0.0.1:${KEYCLOAK_HOST_PORT}"
# Read the same env var compose.yaml's own gateway ports and the KEYCLOAK_ISSUER_URL every
# service checks tokens against derive from (KIBAN_GATEWAY_TLS_HOST_PORT, default 8443), so this
# script works against a stack published on a different port (e.g. the isolated test stack).
gw_base="https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT:-8443}"
realm_url="$kc_base/admin/realms/$KEYCLOAK_REALM"
fake_module_key="kiban_e2e_fake"

psql_c() {
  PGPASSWORD="$KIBAN_DB_PASSWORD" psql -h 127.0.0.1 -p "$POSTGRES_HOST_PORT" -U kiban -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tAc "$1"
}

# --- 1. Keycloak master admin token (same credential bootstrap's own RealmStep/SuperadminStep
#        use) ---
log "fetching a Keycloak master admin token"
admin_token="$(curl -sf -X POST "$kc_base/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=$KC_BOOTSTRAP_ADMIN_USERNAME" -d "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" \
  | jq -r '.access_token')"
[ -n "$admin_token" ] && [ "$admin_token" != "null" ] || fail "could not obtain a Keycloak admin token"
admin_curl() { curl -sf -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" "$@"; }

# --- 2. a direct-grant-capable client (idempotent create-or-reuse), same pattern as
#        infra/e2e-smoke.sh: the realm ships no client with BOTH directAccessGrantsEnabled and a
#        kiban-api audience mapper (that's what this test script itself is proving end-to-end,
#        not something the realm import should pre-bake). ---
login_client_id="kiban-e2e-login"
login_client_secret="e2e-login-$(openssl rand -hex 16)"
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
  log "$login_client_id already exists, resetting its secret"
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
  # $1=username $2=password -> prints access_token
  # Mint through the gateway's OWN `/auth/*` proxy (TLS, self-signed dev
  # cert -> -k), not Keycloak's directly-published host port. Keycloak's `iss` claim
  # (KC_HOSTNAME_STRICT=false) reflects whichever address the CLIENT used to reach the token
  # endpoint — a real browser login always goes through this same gateway proxy, so a token
  # minted via the raw host port carries a DIFFERENT issuer than every real caller's token, and
  # the gateway's own KEYCLOAK_ISSUER_URL (infra/compose.yaml) expects the gateway-origin
  # issuer accordingly (see that file's own comment).
  curl -sfk -X POST "$gw_base/auth/realms/$KEYCLOAK_REALM/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=$login_client_id" -d "client_secret=$login_client_secret" \
    -d "username=$1" -d "password=$2" -d "scope=openid" | jq -r '.access_token // empty'
}

# --- 3. the SEEDED superadmin: bootstrap created it with a forced-temporary password — a direct (password) grant cannot complete Keycloak's UPDATE_PASSWORD
#        required action, so this script (holding the same master-admin credential bootstrap
#        itself uses) clears the required action and sets a known non-temporary password for
#        THIS login proof. On exit (pass or fail) it puts the seeded state back — the password
#        from infra/secrets-in/superadmin-password, temporary, UPDATE_PASSWORD pending — so the
#        playbooks' "log in with the seeded password" stays true after a proof run. ---
superadmin_id="$(admin_curl "$realm_url/users?username=$KIBAN_SUPERADMIN_USERNAME&exact=true" | jq -r '.[0].id // empty')"
[ -n "$superadmin_id" ] || fail "seeded superadmin '$KIBAN_SUPERADMIN_USERNAME' not found in Keycloak — did bootstrap run?"
restore_superadmin() {
  local seeded
  seeded="$(cat infra/secrets-in/superadmin-password 2>/dev/null || true)"
  [ -n "$seeded" ] || { log "WARNING: infra/secrets-in/superadmin-password missing — the seeded password was NOT restored"; return 0; }
  # A fresh master token: the one from step 1 has a 60 s lifetime and the bootstrap re-run
  # (step 9) alone can outlive it.
  admin_token="$(curl -sf -X POST "$kc_base/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$KC_BOOTSTRAP_ADMIN_USERNAME" -d "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" | jq -r '.access_token // empty')"
  admin_curl -X PUT "$realm_url/users/$superadmin_id/reset-password" -d "$(jq -n --arg pw "$seeded" '{type:"password", value:$pw, temporary:true}')" >/dev/null \
    && admin_curl -X PUT "$realm_url/users/$superadmin_id" -d '{"requiredActions": ["UPDATE_PASSWORD"]}' >/dev/null \
    && log "seeded superadmin password restored from infra/secrets-in/superadmin-password (temporary, change forced on first login)" \
    || log "WARNING: could not restore the seeded superadmin password"
}
trap restore_superadmin EXIT
superadmin_login_password="e2e-login-superadmin-$(openssl rand -hex 12)"
admin_curl -X PUT "$realm_url/users/$superadmin_id" -d '{"requiredActions": []}' >/dev/null
admin_curl -X PUT "$realm_url/users/$superadmin_id/reset-password" -d "$(jq -n --arg pw "$superadmin_login_password" '{type:"password", value:$pw, temporary:false}')" >/dev/null

log "password-grant login as the seeded superadmin ($KIBAN_SUPERADMIN_USERNAME)"
superadmin_token="$(password_grant "$KIBAN_SUPERADMIN_USERNAME" "$superadmin_login_password")"
if [ -n "$superadmin_token" ]; then record "superadmin password-grant login" PASS; else record "superadmin password-grant login" FAIL; fi

# --- 4. GET /api/platform/capabilities through the TLS gateway ---
cap_status="$(curl -sk -o /tmp/e2e-login-caps.json -w '%{http_code}' "$gw_base/api/platform/capabilities" -H "Authorization: Bearer $superadmin_token")"
if [ "$cap_status" = "200" ]; then record "GET /api/platform/capabilities -> 200" PASS; else record "GET /api/platform/capabilities -> 200" "FAIL (got $cap_status: $(cat /tmp/e2e-login-caps.json))"; fi

# --- 5. fixture: a fake/test module row (idempotent — catalog UPSERT is always safe per
#        registry's own Seed semantics; the installation row is insert-if-missing so a SECOND
#        run of this script doesn't reset whatever enabled state the FIRST run already proved) ---
psql_c "INSERT INTO platform.module_catalog (module_key, display_name, scope_type, mandatory, base_path, health_path, port, license_class, manifest_version, is_active)
        VALUES ('$fake_module_key', 'Kiban E2E Fake Module', 'global', false, '/api/$fake_module_key', '/health', 9999, 'foundation', '0.0.0-test', true)
        ON CONFLICT (module_key) DO UPDATE SET display_name = EXCLUDED.display_name" >/dev/null
psql_c "INSERT INTO platform.module_installation (module_key, installed, enabled)
        VALUES ('$fake_module_key', true, false)
        ON CONFLICT (module_key) DO NOTHING" >/dev/null

# --- 6. the superadmin mutation: enable the fake module, through the gateway's guard ---
enable_status="$(curl -sk -o /tmp/e2e-login-enable.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/$fake_module_key/enable" -H "Authorization: Bearer $superadmin_token")"
if [ "$enable_status" = "200" ]; then record "POST admin/modules/$fake_module_key/enable (superadmin) -> 200" PASS; else record "POST admin/modules/$fake_module_key/enable (superadmin) -> 200" "FAIL (got $enable_status: $(cat /tmp/e2e-login-enable.json))"; fi

# --- 7. negative case: a real, authenticated, but NON-superadmin caller attempts the SAME
#        mutation -> 403, and (unlike an allowed decision) authz's own handleCan DOES audit a
#        denial (internal/authz/http.go's auditDenial) — this is the natural source of "the
#        authz decision was audited" the exit proof needs (an ALLOWED decision is never itself
#        written to audit.authz__events by design; only denials are). ---
regular_username="kiban-e2e-login-regular"
regular_password="e2e-login-regular-$(openssl rand -hex 12)"
existing_regular_id="$(admin_curl "$realm_url/users?username=$regular_username&exact=true" | jq -r '.[0].id // empty')"
if [ -n "$existing_regular_id" ]; then
  admin_curl -X DELETE "$realm_url/users/$existing_regular_id" >/dev/null
fi
admin_curl -X POST "$realm_url/users" -d "$(jq -n --arg u "$regular_username" --arg pw "$regular_password" '{
  username: $u, email: ($u + "@example.invalid"), firstName: "Kiban", lastName: "E2E Regular",
  enabled: true, emailVerified: true, requiredActions: [],
  credentials: [{type: "password", value: $pw, temporary: false}]
}')" >/dev/null
regular_id="$(admin_curl "$realm_url/users?username=$regular_username&exact=true" | jq -r '.[0].id // empty')"
[ -n "$regular_id" ] || fail "could not resolve the temp regular user's id"

regular_token="$(password_grant "$regular_username" "$regular_password")"
[ -n "$regular_token" ] || fail "password grant for the regular (non-superadmin) user failed"

denied_status="$(curl -sk -o /tmp/e2e-login-denied.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/$fake_module_key/enable" -H "Authorization: Bearer $regular_token")"
if [ "$denied_status" = "403" ]; then record "POST admin/modules/.../enable (non-superadmin) -> 403" PASS; else record "POST admin/modules/.../enable (non-superadmin) -> 403" "FAIL (got $denied_status: $(cat /tmp/e2e-login-denied.json))"; fi

# --- 8. assert BOTH audit rows exist ---
sleep 1 # let both writers' transactions land (both already committed synchronously by the time their HTTP response returned; this is just paranoia against clock skew across containers)
registry_audit_count="$(psql_c "SELECT count(*) FROM audit.registry__events WHERE action = 'platform.module.enable' AND subject = 'module:$fake_module_key'")"
if [ "${registry_audit_count:-0}" -ge 1 ]; then record "registry mutation audited (audit.registry__events)" PASS; else record "registry mutation audited (audit.registry__events)" "FAIL (count=$registry_audit_count)"; fi

authz_audit_count="$(psql_c "SELECT count(*) FROM audit.authz__events WHERE actor = '$regular_id' AND action = 'authz.effective_access.denied'")"
if [ "${authz_audit_count:-0}" -ge 1 ]; then record "authz denial decision audited (audit.authz__events)" PASS; else record "authz denial decision audited (audit.authz__events)" "FAIL (count=$authz_audit_count)"; fi

# --- 9. re-run bootstrap: converged, zero overwrites (operator state wins: the module we
#        just operator-enabled stays enabled through re-bootstrap) ---
log "re-running the bootstrap container"
if docker compose --project-directory infra run --rm bootstrap; then
  record "bootstrap re-run exits 0" PASS
else
  record "bootstrap re-run exits 0" FAIL
fi
recheck_status="$(curl -sk -o /tmp/e2e-login-recheck.json -w '%{http_code}' "$gw_base/api/platform/capabilities/$fake_module_key" -H "Authorization: Bearer $superadmin_token")"
still_enabled="$(jq -r '.data.enabled // false' /tmp/e2e-login-recheck.json 2>/dev/null || echo false)"
if [ "$recheck_status" = "200" ] && [ "$still_enabled" = "true" ]; then
  record "re-bootstrap: fake module stays enabled (zero overwrites)" PASS
else
  record "re-bootstrap: fake module stays enabled (zero overwrites)" "FAIL (status=$recheck_status enabled=$still_enabled)"
fi

# --- 10. the disabled-module 403 path: disable it, then prove the module proxy 403s ---
disable_status="$(curl -sk -o /tmp/e2e-login-disable.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/$fake_module_key/disable" -H "Authorization: Bearer $superadmin_token")"
if [ "$disable_status" = "200" ]; then record "POST admin/modules/$fake_module_key/disable (superadmin) -> 200" PASS; else record "POST admin/modules/$fake_module_key/disable (superadmin) -> 200" "FAIL (got $disable_status)"; fi

# The gateway's catalog snapshot has a 5s TTL (internal/gateway/catalog.go) — poll briefly
# rather than assuming the very next request already sees the fresh snapshot.
proxy_status="000"
proxy_body=""
for _ in 1 2 3 4 5 6 7 8; do
  proxy_status="$(curl -sk -o /tmp/e2e-login-proxy.json -w '%{http_code}' "$gw_base/api/$fake_module_key/anything" -H "Authorization: Bearer $superadmin_token")"
  proxy_body="$(cat /tmp/e2e-login-proxy.json)"
  [ "$proxy_status" = "403" ] && break
  sleep 1
done
if [ "$proxy_status" = "403" ] && echo "$proxy_body" | jq -e '.error.code == "MODULE_DISABLED"' >/dev/null 2>&1; then
  record "disabled-module path -> 403 MODULE_DISABLED" PASS
else
  record "disabled-module path -> 403 MODULE_DISABLED" "FAIL (status=$proxy_status body=$proxy_body)"
fi

# --- 11. the platform role's one record: grant the regular user superadmin through the
#         gateway's superadmin-guarded route -> the SAME mutation that was 403 in step 7 is
#         200 immediately (authz's decision reads the `system:platform#superadmin` tuple live);
#         revoke -> 403 again immediately; the last superadmin cannot revoke themselves (409). ---
role_grant_status="$(curl -sk -o /tmp/e2e-login-role-grant.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/platform-roles" -H "Authorization: Bearer $superadmin_token" -H 'Content-Type: application/json' -d "$(jq -n --arg s "$regular_id" '{subjectId: $s, role: "kiban-superadmin"}')")"
if [ "$role_grant_status" = "200" ]; then record "POST admin/platform-roles (grant regular user) -> 200" PASS; else record "POST admin/platform-roles (grant regular user) -> 200" "FAIL (got $role_grant_status: $(cat /tmp/e2e-login-role-grant.json))"; fi
promoted_status="$(curl -sk -o /tmp/e2e-login-promoted.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/$fake_module_key/disable" -H "Authorization: Bearer $regular_token")"
if [ "$promoted_status" = "200" ]; then record "granted user: admin mutation -> 200 immediately" PASS; else record "granted user: admin mutation -> 200 immediately" "FAIL (got $promoted_status: $(cat /tmp/e2e-login-promoted.json))"; fi
role_revoke_status="$(curl -sk -o /tmp/e2e-login-role-revoke.json -w '%{http_code}' -X DELETE "$gw_base/api/platform/admin/platform-roles/kiban-superadmin/$regular_id" -H "Authorization: Bearer $superadmin_token")"
if [ "$role_revoke_status" = "200" ]; then record "DELETE admin/platform-roles/kiban-superadmin/{regular} -> 200" PASS; else record "DELETE admin/platform-roles/kiban-superadmin/{regular} -> 200" "FAIL (got $role_revoke_status: $(cat /tmp/e2e-login-role-revoke.json))"; fi
demoted_status="$(curl -sk -o /tmp/e2e-login-demoted.json -w '%{http_code}' -X POST "$gw_base/api/platform/admin/modules/$fake_module_key/disable" -H "Authorization: Bearer $regular_token")"
if [ "$demoted_status" = "403" ]; then record "revoked user: admin mutation -> 403 immediately" PASS; else record "revoked user: admin mutation -> 403 immediately" "FAIL (got $demoted_status: $(cat /tmp/e2e-login-demoted.json))"; fi
superadmin_count="$(psql_c "SELECT count(*) FROM authz.tuple WHERE object_type='system' AND object_id='platform' AND relation='superadmin' AND subject_type='user'")"
if [ "${superadmin_count:-0}" = "1" ]; then
  self_revoke_status="$(curl -sk -o /tmp/e2e-login-self-revoke.json -w '%{http_code}' -X DELETE "$gw_base/api/platform/admin/platform-roles/kiban-superadmin/$superadmin_id" -H "Authorization: Bearer $superadmin_token")"
  if [ "$self_revoke_status" = "409" ] && jq -e '.error.code == "CONFLICT"' /tmp/e2e-login-self-revoke.json >/dev/null 2>&1; then record "last superadmin self-revoke -> 409 CONFLICT" PASS; else record "last superadmin self-revoke -> 409 CONFLICT" "FAIL (got $self_revoke_status: $(cat /tmp/e2e-login-self-revoke.json))"; fi
else
  record "last superadmin self-revoke -> 409 CONFLICT" "FAIL (not testable: $superadmin_count superadmin tuples on this stack, expected exactly 1)"
fi
role_audit_count="$(psql_c "SELECT count(*) FROM audit.authz__events WHERE actor = '$superadmin_id' AND subject = 'user:$regular_id' AND action IN ('authz.platform_role.grant', 'authz.platform_role.revoke')")"
if [ "${role_audit_count:-0}" -ge 2 ]; then record "platform-role grant + revoke audited (audit.authz__events)" PASS; else record "platform-role grant + revoke audited (audit.authz__events)" "FAIL (count=$role_audit_count)"; fi

# --- summary table ---
echo
echo "===== e2e-login.sh PASS/FAIL summary ====="
overall=0
for i in "${!RESULT_NAMES[@]}"; do
  status="${RESULT_STATUSES[$i]}"
  printf '%-65s %s\n' "${RESULT_NAMES[$i]}" "$status"
  case "$status" in
    PASS) ;;
    *) overall=1 ;;
  esac
done
echo "============================================"

if [ "$overall" -eq 0 ]; then
  echo "[e2e-login] ALL CHECKS PASSED"
else
  echo "[e2e-login] ONE OR MORE CHECKS FAILED"
fi
exit "$overall"
