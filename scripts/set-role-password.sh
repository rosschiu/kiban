#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Sets/rotates DB role passwords from .env secrets: one `ALTER ROLE <role> PASSWORD` per
# ROLE ENVVAR pair, in one psql session as the app-DB owner (kiban, which has ADMIN
# OPTION on every role its migrations created — infra/postgres-init/02-kiban-owner.sh). Deliberately NOT part of a tern
# migration: migrations are immutable/checksummed and must never embed a secret. ALTER ROLE ...
# PASSWORD is idempotent, so this is safe to re-run on every `make migrate-<x>` / `make dev`.
#
# Usage: scripts/set-role-password.sh ROLE ENVVAR [ROLE ENVVAR...]
#   e.g. scripts/set-role-password.sh kiban_docs KIBAN_DOCS_DB_PASSWORD
# Callers: migrations/registry/set-role-passwords.sh (the four foundation roles, also run by
# internal/bootstrap's MigrationsStep), the Makefile's migrate-<module> targets and
# infra/migrate-entrypoint.sh (one module role each).
set -euo pipefail

if [ $# -lt 2 ] || [ $(($# % 2)) -ne 0 ]; then
  echo "usage: $0 ROLE ENVVAR [ROLE ENVVAR...]" >&2
  exit 2
fi

: "${POSTGRES_DB:?POSTGRES_DB not set}"
: "${KIBAN_DB_PASSWORD:?KIBAN_DB_PASSWORD not set}"

# Every password must be present before the first ALTER runs (never a half-rotated set).
psql_vars=()
sql=""
while [ $# -gt 0 ]; do
  role="$1"; var="$2"; shift 2
  [ -n "${!var:-}" ] || { echo "set-role-password: $var not set" >&2; exit 1; }
  psql_vars+=(-v "${role}_pw=${!var}")
  sql+="ALTER ROLE ${role} PASSWORD :'${role}_pw';"$'\n'
done

# KIBAN_DB_HOST/KIBAN_DB_PORT: host-run default is 127.0.0.1/POSTGRES_HOST_PORT; the compose
# `migrate` service (infra/compose.yaml) sets postgres/5432 — same parametrization
# migrations/*/tern.conf uses.
: "${POSTGRES_HOST_PORT:=}"
db_host="${KIBAN_DB_HOST:-127.0.0.1}"
db_port="${KIBAN_DB_PORT:-$POSTGRES_HOST_PORT}"
if [ -z "$db_port" ]; then
  echo "set-role-password: neither KIBAN_DB_PORT nor POSTGRES_HOST_PORT is set" >&2
  exit 1
fi

export PGPASSWORD="$KIBAN_DB_PASSWORD"

printf '%s' "$sql" | psql -v ON_ERROR_STOP=1 -h "$db_host" -p "$db_port" -U kiban -d "$POSTGRES_DB" "${psql_vars[@]}"
