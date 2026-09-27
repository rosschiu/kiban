#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# The four foundation roles internal/bootstrap/migrate.go's MigrationsStep knows about
# (deps.RolePasswords) — bootstrap execs this path directly, so it stays; the work is
# scripts/set-role-password.sh's. Module roles are set by `make migrate-<key>` /
# infra/migrate-entrypoint.sh calling that script with the module's own pair.
exec "$(dirname "$0")/../../scripts/set-role-password.sh" \
  kiban_registry KIBAN_REGISTRY_DB_PASSWORD \
  kiban_identity KIBAN_IDENTITY_DB_PASSWORD \
  kiban_org KIBAN_ORG_DB_PASSWORD \
  kiban_authz KIBAN_AUTHZ_DB_PASSWORD
