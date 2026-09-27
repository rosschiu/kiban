-- SPDX-License-Identifier: Apache-2.0

-- The registry's Seed()/SetEnabled() paths install/toggle each module's authz.fragment.json into
-- authz.model_fragment (internal/registry/authzfragment.go), alongside the
-- platform.module_catalog/module_installation rows Seed owns — same root cause as
-- migrations/registry/0006_notification_audit_usage.sql (a runtime role needing a grant on a
-- table owned by ANOTHER service's schema, hand-authored because no module/schema-owned
-- provisioning workflow exists yet). This grant has to live HERE (in
-- migrations/authz, not migrations/registry) because authz.model_fragment doesn't exist until
-- migrations/authz/0002_authz_tables.sql runs, and `make migrate-registry` always runs BEFORE
-- `make migrate-authz` (Makefile / infra/migrate-entrypoint.sh ordering — kiban_registry's own
-- role is created first, everything else grants against it afterward). No DELETE: the fragment
-- installer only ever inserts/updates a row (active=false on disable, never a row delete —
-- a disabled module's fragment stays on record).
-- Table grants alone are insufficient — Postgres also enforces schema-level USAGE (the exact
-- gap migrations/registry/0006_notification_audit_usage.sql's own comment documents for the
-- audit schema).
GRANT USAGE ON SCHEMA authz TO kiban_registry;
GRANT SELECT, INSERT, UPDATE ON authz.model_fragment TO kiban_registry;

---- create above / drop below ----

REVOKE SELECT, INSERT, UPDATE ON authz.model_fragment FROM kiban_registry;
REVOKE USAGE ON SCHEMA authz FROM kiban_registry;
