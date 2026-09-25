#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# `kiban`: the non-superuser owner of the application database (POSTGRES_DB, created by the
# image for the superuser and handed over here). Every migration (`AUTHORIZATION kiban` in
# migrations/*/, tern.conf's `user = kiban`), scripts/set-role-password.sh and cmd/bootstrap
# connect as it. CREATEROLE covers migrations/registry/*_role.sql's CREATE ROLE (PG16+: the
# creator gets ADMIN OPTION on those roles, which is what ALTER ROLE ... PASSWORD needs); owning
# the database covers CREATE SCHEMA, GRANT CONNECT and the trusted extensions (pgcrypto,
# btree_gist). No CREATEDB, no BYPASSRLS, no superuser. Only `kiban` and the roles migrations
# GRANT CONNECT to may connect (`keycloak` cannot). A cluster created before this script
# existed has `kiban` as its bootstrap superuser, which cannot be demoted — recreate it
# (see the Operating page of the documentation).
: "${KIBAN_DB_PASSWORD:?KIBAN_DB_PASSWORD not set}"
# The database name is fixed: shipped, checksum-frozen migrations (migrations/registry/
# 0001/0005/0008/0010/0012) `GRANT CONNECT ON DATABASE kiban` by literal and run first on a fresh
# cluster, so any other POSTGRES_DB fails at `migrate`. Fail here instead, at first start.
[ "$POSTGRES_DB" = kiban ] || { echo "POSTGRES_DB must be 'kiban' (got '$POSTGRES_DB'): the shipped migrations name the database by literal — see the Operating page of the documentation" >&2; exit 1; }

psql -v ON_ERROR_STOP=1 -v pw="$KIBAN_DB_PASSWORD" -v db="$POSTGRES_DB" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE kiban LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOBYPASSRLS PASSWORD :'pw';
ALTER DATABASE :"db" OWNER TO kiban;
REVOKE CONNECT ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO kiban;
SQL
