#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# Dedicated Keycloak role + database, separate from the application database. Runs once at
# initdb (docker-entrypoint-initdb.d) as POSTGRES_USER, the cluster superuser — the ONLY place
# it is used: Keycloak itself connects as `keycloak` (KC_DB_USERNAME/KC_DB_PASSWORD in
# infra/compose.yaml), which owns nothing but its own database and cannot connect to the app DB.
# No `set -e`: a ConfigMap mount (deploy/k8s) is sourced into the image entrypoint, not
# executed; ON_ERROR_STOP + the entrypoint's own -e fail it either way.
: "${KC_DB_PASSWORD:?KC_DB_PASSWORD not set}"

psql -v ON_ERROR_STOP=1 -v pw="$KC_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'pw';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE CONNECT ON DATABASE keycloak FROM PUBLIC;
SQL
