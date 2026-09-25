-- SPDX-License-Identifier: Apache-2.0

-- schema `platform` is registry-owned exclusively. schema `audit` is shared:
-- every service creates its own `audit.<module>__<name>` tables inside it — IF NOT EXISTS because later
-- services' migrations run this same statement against the one shared `kiban` database.
CREATE SCHEMA platform AUTHORIZATION kiban;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA platform TO kiban_registry;
GRANT USAGE ON SCHEMA audit TO kiban_registry, kiban_identity, kiban_org, kiban_authz;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA platform FROM kiban_registry;
REVOKE USAGE ON SCHEMA audit FROM kiban_registry, kiban_identity, kiban_org, kiban_authz;
DROP SCHEMA platform CASCADE;
-- audit schema is shared; never dropped by a single service's migration.
