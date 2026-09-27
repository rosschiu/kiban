-- SPDX-License-Identifier: Apache-2.0

-- schema `timesheet` is timesheet-owned exclusively. The role
-- `kiban_timesheet` is created by the platform's shared role migration
-- (migrations/registry/0008_timesheet_role.sql — same gap notification hit: no module-owned DB
-- role provisioning path exists yet).
CREATE SCHEMA timesheet AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA timesheet TO kiban_timesheet;

GRANT SELECT ON public.schema_version_timesheet TO kiban_timesheet;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_timesheet FROM kiban_timesheet;
REVOKE USAGE ON SCHEMA timesheet FROM kiban_timesheet;
DROP SCHEMA timesheet CASCADE;
