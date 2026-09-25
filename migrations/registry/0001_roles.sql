-- SPDX-License-Identifier: Apache-2.0

-- Per-service DB roles: kiban_registry / kiban_identity / kiban_org / kiban_authz. Created here
-- because the registry is the first foundation service to migrate; each later service's own migrations
-- grant privileges on its own schema to its own role, and bootstrap re-verifies all four exist.
-- LOGIN with no password: passwords are set out-of-band by
-- migrations/registry/set-role-passwords.sh from .env secrets, never committed here.
CREATE ROLE kiban_registry LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE kiban_identity LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE kiban_org      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE kiban_authz    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE kiban TO kiban_registry, kiban_identity, kiban_org, kiban_authz;

-- tern creates its version table before running any migration file, so it already exists here.
-- The service checks it at startup (migrations-check, NOT run) to fail loudly
-- with a clear message instead of an opaque "relation does not exist" the first time it queries
-- an actual table.
GRANT SELECT ON public.schema_version_registry TO kiban_registry;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_registry FROM kiban_registry;
REVOKE CONNECT ON DATABASE kiban FROM kiban_registry, kiban_identity, kiban_org, kiban_authz;
DROP ROLE kiban_registry;
DROP ROLE kiban_identity;
DROP ROLE kiban_org;
DROP ROLE kiban_authz;
