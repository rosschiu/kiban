#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# The one live-stack guard every proof script shares (infra/e2e-*.sh, modules/*/curl-proof.sh,
# modules/notification/restart-survival-proof.sh; web/e2e-shared/env.ts is the TypeScript twin).
# Sourced, never run; the caller defines `fail` and has cd'd to the repo root.
#
#   . infra/proof-env.sh
#   proof_env .env.test     # the isolated kiban-test stack (the curl-proofs)
#   proof_env .env          # the `make dev` stack (the e2e scripts)
#
# proof_env sources the env file (set -a) and then refuses when infra/.public-mode is present
# (`make public-up` writes it; `make dev`/`dev-clean` remove it) AND a port this script mutates
# through resolves to .env's own live value — an .env caller always matches, an
# .env.test caller only if its remap collapsed onto the public stack's ports.
proof_env() {
  local env_file="$1" name live cur
  if [ ! -f "$env_file" ]; then
    if [ "$env_file" = .env ]; then
      fail ".env not found — copy .env.example and fill it in first"
    fi
    fail "$env_file not found — run \`make test-stack-up\` first (this script targets ONLY the isolated kiban-test stack, never .env's live stack)"
  fi
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
  [ -f infra/.public-mode ] && [ -f .env ] || return 0
  for name in POSTGRES_HOST_PORT KEYCLOAK_HOST_PORT KIBAN_GATEWAY_TLS_HOST_PORT; do
    live="$(grep -E "^$name=" .env | cut -d= -f2- || true)"
    cur="${!name:-}"
    if [ "$name" = KIBAN_GATEWAY_TLS_HOST_PORT ]; then
      live="${live:-8443}"
      cur="${cur:-8443}"
    fi
    if [ -n "$live" ] && [ "$cur" = "$live" ]; then
      fail "resolved $name matches .env's live value while infra/.public-mode is present (the stack is PUBLIC — \`make public-up\`) — refusing; use \`make test-stack-up\` and target that isolated stack instead"
    fi
  done
}
