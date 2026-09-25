-- SPDX-License-Identifier: Apache-2.0

-- Same root cause as 0005_notification_role.sql: the shared
-- `audit` schema's USAGE grant is a hand-enumerated role list in
-- migrations/registry/0002_schemas.sql ("GRANT USAGE ON SCHEMA audit TO kiban_registry,
-- kiban_identity, kiban_org, kiban_authz") — immutable/shipped, so it could not simply gain a
-- fifth name. Every module's audit writer (internal/audit — "the platform's ONE audit writer")
-- needs USAGE on this schema to INSERT its own audit.<moduleKey>__* table; without this grant,
-- modules/notification/migrations/0003_audit.sql's own per-table GRANT SELECT, INSERT is
-- necessary but not sufficient (Postgres also enforces schema-level USAGE).
GRANT USAGE ON SCHEMA audit TO kiban_notification;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA audit FROM kiban_notification;
