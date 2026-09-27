#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# `make setup` — toolchain preflight + one-time env scaffold.
#
# Scope:
#   1. Verify/report the host toolchain (docker + compose plugin, go, node/npm). docker + the
#      compose plugin are HARD requirements (every `make dev`/`make public-up` build happens
#      INSIDE containers via infra/Dockerfile.service — see its own header comment — so nothing
#      else on the host needs go/node/npm to run the one-command deploy path; this script never
#      sudo-installs anything, it only checks and reports). go/node/npm are reported so a
#      contributor doing local (non-container) `make check`/`go test`/`web-check` work learns
#      immediately if their host toolchain doesn't match go.mod / web/package.json's declared
#      versions, but a mismatch or absence there does NOT fail `make setup` — the deploy path
#      doesn't need them.
#   2. Scaffold .env from .env.example, generating a value for every secret field
#      that ships blank in the example, but ONLY when .env does not already exist —
#      write-once, never regenerates a value that's already there (regenerating would drift
#      from the passwords already applied to an existing database).
#   3. Prepare infra/secrets-in/ (0700 dir) — the one-time superadmin password's home
#      (infra/compose.yaml's `bootstrap` service). Idempotent for the same write-once
#      reason: never overwrites an existing password file.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

log() { echo "[setup] $*"; }
warn() { echo "[setup] WARN: $*"; }
fail_hard=0

echo "===== make setup: host toolchain preflight ====="

# --- docker (hard requirement) ---
if command -v docker >/dev/null 2>&1; then
  docker_version="$(docker --version 2>/dev/null || echo unknown)"
  log "PASS  docker found: $docker_version"
else
  log "FAIL  docker not found on PATH — install it yourself (see https://docs.docker.com/engine/install/); this script will not sudo-install it"
  fail_hard=1
fi

# --- docker compose plugin (hard requirement) ---
if docker compose version >/dev/null 2>&1; then
  compose_version="$(docker compose version 2>/dev/null || echo unknown)"
  log "PASS  docker compose plugin found: $compose_version"
else
  log "FAIL  'docker compose' plugin not found — install it yourself (see https://docs.docker.com/compose/install/); this script will not sudo-install it"
  fail_hard=1
fi

# --- go (soft: needed for local `make check`/`go test`, NOT for `make dev`/`make setup`'s own
#     deploy path — every service builds inside infra/Dockerfile.service's `builder` stage) ---
go_want="$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod | head -1)"
if command -v go >/dev/null 2>&1; then
  go_have="$(go version | sed -n 's/^go version go\([0-9.]*\).*/\1/p')"
  log "PASS  go found: $go_have (go.mod wants $go_want — only load-bearing for local, non-container \`go test\`/\`make check\`)"
else
  warn "go not found on PATH — fine for \`make dev\`/\`make setup\` (builds happen inside containers); needed only for local, non-container \`make check\`/\`go test\`. go.mod wants $go_want."
fi

# --- node / npm (soft: same reasoning — web/Dockerfile stage builds the shell bundle inside
#     the gateway image; host node/npm only matters for local, non-container \`make web-check\`) ---
node_want="$(sed -n 's/.*"node": *">=\([0-9]*\)".*/\1/p' web/package.json | head -1)"
if command -v node >/dev/null 2>&1; then
  node_have="$(node --version)"
  log "PASS  node found: $node_have (web/package.json wants >=${node_want:-?} — only load-bearing for local, non-container \`make web-check\`)"
else
  warn "node not found on PATH — fine for \`make dev\`/\`make setup\`; needed only for local, non-container \`make web-check\`. web/package.json wants >=${node_want:-?}."
fi
if command -v npm >/dev/null 2>&1; then
  npm_have="$(npm --version)"
  log "PASS  npm found: $npm_have"
else
  warn "npm not found on PATH — same reasoning as node above."
fi

if [ "$fail_hard" -ne 0 ]; then
  echo "===== make setup: FAILED (missing hard requirement — see FAIL lines above) ====="
  exit 1
fi

echo "===== make setup: .env ====="

# Secret fields .env.example ships blank (grep the source of truth rather than
# hardcoding the list twice, so a new blank secret field is picked up automatically).
secret_keys="$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)= *\(#.*\)\{0,1\}$/\1/p' .env.example)"

if [ -f .env ]; then
  log ".env already exists — leaving every value exactly as-is (write-once; never regenerated)"
else
  log ".env not found — scaffolding from .env.example"
  cp .env.example .env && chmod 600 .env
  for key in $secret_keys; do
    # Hex, not base64. Every service builds its Postgres DSN as a plain
    # `fmt.Sprintf("postgres://%s:%s@host:port/db", user, password)` (cmd/*/main.go,
    # internal/bootstrap/migrate.go — no URL escaping), so a generated secret containing a
    # URL-meaningful character such as `/` breaks DSN parsing ("cannot parse ... invalid port
    # after host"). Hex output ([0-9a-f] only, 48 chars from 24 bytes) is never URL-meaningful
    # and needs no encoding anywhere a generated secret ends up embedded (DSN, HTTP header,
    # shell arg).
    value="$(openssl rand -hex 24)"
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  done
  log "generated a value for each of: $(echo "$secret_keys" | tr '\n' ' ')"
  log ".env created — review it, especially KIBAN_SUPERADMIN_USERNAME/EMAIL, before a real deploy"
fi

echo "===== make setup: infra/secrets-in ====="
mkdir -p infra/secrets-in
chmod 700 infra/secrets-in
log "infra/secrets-in/ ready (the one-time superadmin password lands here on first \`make dev\`/\`make public-up\`, never regenerated after)"

echo "===== make setup: DONE ====="
echo "Next: make dev   (or: make setup && make dev)"
