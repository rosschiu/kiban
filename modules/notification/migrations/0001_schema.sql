-- SPDX-License-Identifier: Apache-2.0

-- schema `notification` is notification-owned exclusively (a module's SQL lives in its own
-- schema). The role `kiban_notification` is created by the platform's
-- shared role migration (migrations/registry/0005_notification_role.sql: no module-owned-role
-- provisioning path exists yet, so a foundation migration was required to create it).
CREATE SCHEMA notification AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA notification TO kiban_notification;

-- migrations-check (NOT run) mirrors every other service's CheckMigrationsApplied pattern,
-- against this module's own tern version table.
GRANT SELECT ON public.schema_version_notification TO kiban_notification;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_notification FROM kiban_notification;
REVOKE USAGE ON SCHEMA notification FROM kiban_notification;
DROP SCHEMA notification CASCADE;
