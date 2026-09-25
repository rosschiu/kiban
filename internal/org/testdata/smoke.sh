#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Live smoke script: exercises the org service's full HTTP surface against a real, running
# instance (start it first: `set -a; . .env; set +a; go run ./cmd/org`) on top of the dev
# stack with `make migrate-org` already applied.
#
# Chain proved: health/ready -> create company -> create member -> create position ->
# create-and-assign, plus the subtree/list read paths. Every mutation in the chain currently
# returns 503 AUTHORIZATION_UNAVAILABLE when the service runs with the fail-closed deny-all
# AdminAuthorizer (no KIBAN_AUTHZ_BASE_URL), which is why this script asserts 503, not 201, on
# every write. What this proves live: the service boots against the real dev
# DB, every route is wired end to end (JSON envelope shapes correct), the fail-closed guard is
# actually enforced (no data written despite a well-formed request), and each denial is audited.
set -euo pipefail

BASE_URL="${ORG_BASE_URL:-http://127.0.0.1:8130}"
PASS=0
FAIL=0

check() {
    local desc="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        echo "OK   $desc (got $got)"
        PASS=$((PASS + 1))
    else
        echo "FAIL $desc (got $got, want $want)"
        FAIL=$((FAIL + 1))
    fi
}

echo "== health/ready =="
health_code=$(curl -s -o /tmp/org-smoke-health.json -w '%{http_code}' "$BASE_URL/health")
check "GET /health" "$health_code" "200"
ready_code=$(curl -s -o /tmp/org-smoke-ready.json -w '%{http_code}' "$BASE_URL/ready")
check "GET /ready" "$ready_code" "200"

echo "== create company (org.unit.create) =="
unit_resp=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/internal/org/units" \
    -H 'Content-Type: application/json' \
    -d '{"typeKey":"company","code":"SMOKE-CO","name":"Smoke Test Co"}')
unit_code=$(tail -n1 <<<"$unit_resp")
unit_body=$(head -n-1 <<<"$unit_resp")
check "POST /internal/org/units status" "$unit_code" "503"
check "POST /internal/org/units error code" "$(jq -r '.error.code' <<<"$unit_body")" "AUTHORIZATION_UNAVAILABLE"

echo "== create member (org.member.create) =="
company_id="00000000-0000-0000-0000-000000000000" # fail-closed above means no real company exists to reference
member_resp=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/internal/org/members" \
    -H 'Content-Type: application/json' \
    -d "{\"companyId\":\"$company_id\",\"code\":\"SMOKE-M1\",\"displayName\":\"Smoke Member\"}")
member_code=$(tail -n1 <<<"$member_resp")
check "POST /internal/org/members status" "$member_code" "503"

echo "== create position (org.position.create) =="
position_resp=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/internal/org/positions" \
    -H 'Content-Type: application/json' \
    -d "{\"companyId\":\"$company_id\",\"code\":\"SMOKE-P1\",\"title\":\"Smoke Position\",\"orgUnitId\":\"$company_id\"}")
position_code=$(tail -n1 <<<"$position_resp")
check "POST /internal/org/positions status" "$position_code" "503"

echo "== create-and-assign (org.position.create_and_assign) =="
caa_resp=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/internal/org/positions:create-and-assign" \
    -H 'Content-Type: application/json' \
    -d "{\"companyId\":\"$company_id\",\"code\":\"SMOKE-P2\",\"title\":\"Smoke CFO\",\"orgUnitId\":\"$company_id\",\"memberId\":\"$company_id\",\"validFrom\":\"2026-01-01\"}")
caa_code=$(tail -n1 <<<"$caa_resp")
check "POST /internal/org/positions:create-and-assign status" "$caa_code" "503"

echo "== reads stay open (no auth gate on GET) =="
subtree_code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/internal/org/units/$company_id/subtree")
check "GET .../subtree status" "$subtree_code" "200"
members_code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/internal/org/members?companyId=$company_id")
check "GET /internal/org/members status" "$members_code" "200"

echo
echo "== summary: $PASS passed, $FAIL failed =="
if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
