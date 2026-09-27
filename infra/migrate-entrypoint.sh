#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Compose's one-shot `migrate` service entrypoint. Applies every service's and module's
# tern migrations, in the one order that matters (registry first — it creates the per-service
# DB roles + shared schemas every later migration grants against; migrations/identity/
# 0001_schema.sql's own header names this as a hard dependency; authz before identity — authz's
# migrations only reference roles, and migrations/authz/0010 must backfill the superadmin tuples
# before migrations/identity/0005 drops identity.platform_role), then sets the four DB role
# passwords (scripts/set-role-password.sh via migrations/registry/set-role-passwords.sh — idempotent,
# safe to re-run on every `make dev`) and each module's own role password. Everything connects as
# the app-DB owner `kiban` (KIBAN_DB_PASSWORD; infra/postgres-init/02-kiban-owner.sh), never the
# superuser. Runs inside the `builder` Docker stage (infra/Dockerfile.service), so `go tool
# tern` and `psql` are both on PATH and /src is the full repo source.
set -eu

export KIBAN_DB_HOST="${KIBAN_DB_HOST:-postgres}"
export KIBAN_DB_PORT="${KIBAN_DB_PORT:-5432}"

cd /src

echo "migrate: applying registry migrations"
go tool tern migrate -m migrations/registry -c migrations/registry/tern.conf
./migrations/registry/set-role-passwords.sh

echo "migrate: applying authz migrations"
go tool tern migrate -m migrations/authz -c migrations/authz/tern.conf

echo "migrate: applying identity migrations"
go tool tern migrate -m migrations/identity -c migrations/identity/tern.conf

echo "migrate: applying org migrations"
go tool tern migrate -m migrations/org -c migrations/org/tern.conf

echo "migrate: applying notification module migrations"
go tool tern migrate -m modules/notification/migrations -c modules/notification/migrations/tern.conf
./scripts/set-role-password.sh kiban_notification KIBAN_NOTIFICATION_DB_PASSWORD

echo "migrate: applying timesheet module migrations"
go tool tern migrate -m modules/timesheet/migrations -c modules/timesheet/migrations/tern.conf
./scripts/set-role-password.sh kiban_timesheet KIBAN_TIMESHEET_DB_PASSWORD

echo "migrate: applying docs module migrations"
go tool tern migrate -m modules/docs/migrations -c modules/docs/migrations/tern.conf
./scripts/set-role-password.sh kiban_docs KIBAN_DOCS_DB_PASSWORD

echo "migrate: applying helpdesk module migrations"
go tool tern migrate -m modules/helpdesk/migrations -c modules/helpdesk/migrations/tern.conf
./scripts/set-role-password.sh kiban_helpdesk KIBAN_HELPDESK_DB_PASSWORD

echo "migrate: all migrations applied"
