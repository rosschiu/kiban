-- SPDX-License-Identifier: Apache-2.0

-- schema `docs` is docs-owned exclusively. The role `kiban_docs` is
-- created by the platform's shared role migration (migrations/registry/0010_docs_role.sql — same
-- gap as notification's/timesheet's own role migrations: no module-owned role-provisioning path
-- exists yet).
CREATE SCHEMA docs AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA docs TO kiban_docs;

-- migrations-check (NOT run) mirrors every other service's CheckMigrationsApplied pattern,
-- against this module's own tern version table.
GRANT SELECT ON public.schema_version_docs TO kiban_docs;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_docs FROM kiban_docs;
REVOKE USAGE ON SCHEMA docs FROM kiban_docs;
DROP SCHEMA docs CASCADE;
