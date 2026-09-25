-- SPDX-License-Identifier: Apache-2.0

-- Modules get their own postgres schema with a runtime role that has no DDL rights — but no
-- module-owned role-provisioning path exists yet: every per-service runtime role
-- (kiban_registry/identity/org/authz) was hand-created once, together, in
-- migrations/registry/0001_roles.sql (immutable/checksummed — cannot be edited to add a fifth
-- role). So a module cannot get its own runtime DB role without a foundation migration.
-- This migration is the minimal fix: one new role, same shape
-- as 0001_roles.sql's four, so `make migrate-notification` (and every later module) has
-- something to grant its own schema to.
CREATE ROLE kiban_notification LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE kiban TO kiban_notification;

-- Unlike 0001_roles.sql, no GRANT SELECT ON its own schema_version_* table here: that table
-- doesn't exist yet at registry-migrate time (it's created when `make migrate-notification`
-- first runs tern against modules/notification/migrations). notification/0001_schema.sql grants
-- it directly instead, once tern has created it — same effect, different ordering.

---- create above / drop below ----

REVOKE CONNECT ON DATABASE kiban FROM kiban_notification;
DROP ROLE kiban_notification;
