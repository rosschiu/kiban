-- SPDX-License-Identifier: Apache-2.0

-- schema `org` is org-owned exclusively (same layout as registry and identity). Roles
-- (kiban_org among them) and the shared `audit` schema already exist
-- (migrations/registry/0001_roles.sql, 0002_schemas.sql must run first). USAGE on schema
-- `identity` was already granted to kiban_org by
-- migrations/identity/0001_schema.sql, so org can SELECT identity.user_read_v without
-- any further grant here.
CREATE SCHEMA org AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA org TO kiban_org;

-- migrations-check (NOT run) uses the same CheckMigrationsApplied pattern as registry/identity, against this
-- service's own tern version table.
GRANT SELECT ON public.schema_version_org TO kiban_org;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_org FROM kiban_org;
REVOKE USAGE ON SCHEMA org FROM kiban_org;
DROP SCHEMA org CASCADE;
