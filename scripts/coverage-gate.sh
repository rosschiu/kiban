#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Coverage ratchet gate.
#
# Runs the Go and web (vitest, both web/sdk and web/shell) test suites with coverage
# instrumentation, computes per-scope statement coverage for the scopes defined in
# tools/coveragegate, and compares each against coverage/ratchet.json.
#
# Ratchet rule: ratchet.json's "min" per scope is what this gate enforces today; "floor" is the
# target (95% security-critical, 80% general). "min" is raised toward "floor" as tests are added
# — a scope is "done" when min == floor. Minimums may only ever increase, never decrease; this
# script does not enforce that (kept simple, dependency-free) — `make ratchet-guard` does.
#
# Modes (arg 1, default "gate"):
#   gate    - exit 1 if any scope is below its ratchet min (wired into `make check`).
#   report  - always exit 0; prints current coverage + gap-to-floor per scope
#             (`make coverage-report`).
#
# Requires a live stack (`make test-stack-up`) — the security-critical Go scopes (identity,
# bootstrap realm+seed, gateway token+guard+proxy) only reach their real coverage under
# `-tags live` (live Postgres/Keycloak).
set -euo pipefail

MODE="${1:-gate}"
if [[ "$MODE" != "gate" && "$MODE" != "report" ]]; then
  echo "usage: $0 [gate|report]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p coverage web/sdk/coverage web/shell/coverage

echo "== coverage-gate: running Go tests with coverage (-tags live; needs the dev stack) =="
# -count=1 disables Go's test-result cache: several of these packages (internal/bootstrap,
# internal/identity, internal/gateway, ...) hold `-tags live` integration tests whose observed
# coverage depends on the LIVE stack's current state (e.g. whether Keycloak's realm is already
# converged) — a state the Go toolchain has no way to see. Without -count=1, an unchanged source
# tree lets `go test` silently replay a STALE cached coverage profile from a run against a
# different (or since-torn-down) live stack, producing coverage numbers that don't reflect
# reality (a stale cached profile from a since-changed stack state looks like flaky coverage,
# not a genuinely nondeterministic live branch).
go test -p 1 -count=1 -tags live -coverprofile=coverage/go.out -coverpkg=./internal/...,./cmd/...,./modules/...,./modulekit/... ./...

echo "== coverage-gate: running web/sdk vitest coverage =="
(cd web && npm run -w sdk test:coverage)

echo "== coverage-gate: running web/shell vitest coverage =="
(cd web && npm run -w shell test:coverage)

echo "== coverage-gate: evaluating scopes against coverage/ratchet.json =="
go run ./tools/coveragegate -mode "$MODE" \
  -ratchet coverage/ratchet.json \
  -go-profile coverage/go.out \
  -web-summary web/sdk/coverage/coverage-summary.json \
  -web-src-dir web/sdk/src \
  -web-shell-summary web/shell/coverage/coverage-summary.json \
  -web-shell-src-dir web/shell/src
