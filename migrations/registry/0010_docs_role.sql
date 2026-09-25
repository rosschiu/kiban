-- SPDX-License-Identifier: Apache-2.0

-- Same gap notification's/timesheet's own role migrations hit (no module-owned DB role
-- provisioning path exists yet): the docs module needs its own runtime role, hand-created here exactly like
-- migrations/registry/0005_notification_role.sql and 0008_timesheet_role.sql before it.
CREATE ROLE kiban_docs LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE kiban TO kiban_docs;

-- No GRANT SELECT ON its own schema_version_* table here: that table doesn't exist yet at
-- registry-migrate time (created when `make migrate-docs` first runs tern). See
-- the docs module's own 0001_schema.sql migration, which grants it directly once tern has created it.

---- create above / drop below ----

REVOKE CONNECT ON DATABASE kiban FROM kiban_docs;
DROP ROLE kiban_docs;
