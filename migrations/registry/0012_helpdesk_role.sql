-- SPDX-License-Identifier: Apache-2.0

-- Same gap notification's/timesheet's/docs's own role migrations hit
-- (no module-owned DB role provisioning path exists yet):
-- the helpdesk module needs its own runtime role, hand-created here exactly like
-- migrations/registry/0005_notification_role.sql, 0008_timesheet_role.sql, and
-- 0010_docs_role.sql before it.
CREATE ROLE kiban_helpdesk LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE kiban TO kiban_helpdesk;

-- No GRANT SELECT ON its own schema_version_* table here: that table doesn't exist yet at
-- registry-migrate time (created when `make migrate-helpdesk` first runs tern). See
-- modules/helpdesk/migrations/0001_schema.sql, which grants it directly once tern has created it.

---- create above / drop below ----

REVOKE CONNECT ON DATABASE kiban FROM kiban_helpdesk;
DROP ROLE kiban_helpdesk;
