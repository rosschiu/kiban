-- SPDX-License-Identifier: Apache-2.0

-- schema `authz` is authz-owned exclusively (same layout as registry, identity and org).
-- Roles (kiban_authz among them) and the shared `audit` schema already exist
-- (migrations/registry/0001_roles.sql, 0002_schemas.sql must run first; 0002_schemas.sql already
-- granted kiban_authz USAGE ON SCHEMA audit).
CREATE SCHEMA authz AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA authz TO kiban_authz;

-- migrations-check (NOT run) uses the same CheckMigrationsApplied pattern as the other services, against
-- this service's own tern version table.
GRANT SELECT ON public.schema_version_authz TO kiban_authz;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_authz FROM kiban_authz;
REVOKE USAGE ON SCHEMA authz FROM kiban_authz;
DROP SCHEMA authz CASCADE;
