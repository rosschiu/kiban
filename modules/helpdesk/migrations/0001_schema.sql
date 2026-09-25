-- SPDX-License-Identifier: Apache-2.0

-- schema `helpdesk` is helpdesk-owned exclusively. The role `kiban_helpdesk`
-- is created by the platform's shared role migration (migrations/registry/0012_helpdesk_role.sql
-- — same gap as notification's/timesheet's/docs's own role
-- migrations: no module-owned role-provisioning path exists yet).
CREATE SCHEMA helpdesk AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA helpdesk TO kiban_helpdesk;

-- migrations-check (NOT run) mirrors every other service's CheckMigrationsApplied pattern,
-- against this module's own tern version table.
GRANT SELECT ON public.schema_version_helpdesk TO kiban_helpdesk;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_helpdesk FROM kiban_helpdesk;
REVOKE USAGE ON SCHEMA helpdesk FROM kiban_helpdesk;
DROP SCHEMA helpdesk CASCADE;
