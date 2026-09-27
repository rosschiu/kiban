-- SPDX-License-Identifier: Apache-2.0

-- No module-owned DB role provisioning path exists yet, so the timesheet module needs the same hand-authored
-- foundation migration notification's own migrations/registry/0005_notification_role.sql needed.
CREATE ROLE kiban_timesheet LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE kiban TO kiban_timesheet;

-- No GRANT SELECT ON its own schema_version_* table here: that table doesn't exist yet at
-- registry-migrate time (created when `make migrate-timesheet` first runs tern). See
-- timesheet/migrations/0001_schema.sql, which grants it directly once tern has created it.

---- create above / drop below ----

REVOKE CONNECT ON DATABASE kiban FROM kiban_timesheet;
DROP ROLE kiban_timesheet;
