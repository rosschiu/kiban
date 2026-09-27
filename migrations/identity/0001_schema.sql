-- SPDX-License-Identifier: Apache-2.0

-- schema `identity` is identity-owned exclusively (same layout as registry's).
-- Roles (kiban_identity, kiban_org, kiban_authz, kiban_registry) and the shared `audit` schema
-- already exist (migrations/registry/0001_roles.sql, 0002_schemas.sql must run first). USAGE on
-- schema `identity` is granted to kiban_identity (full owner access) and to kiban_org/kiban_authz
-- (Postgres requires schema USAGE to SELECT from any object inside it, including the published
-- identity.user_read_v view; base tables stay ungranted to those roles).
CREATE SCHEMA identity AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA identity TO kiban_identity, kiban_org, kiban_authz;

-- migrations-check (NOT run) uses the same CheckMigrationsApplied pattern as registry, against this
-- service's own tern version table.
GRANT SELECT ON public.schema_version_identity TO kiban_identity;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_identity FROM kiban_identity;
REVOKE USAGE ON SCHEMA identity FROM kiban_identity, kiban_org, kiban_authz;
DROP SCHEMA identity CASCADE;
