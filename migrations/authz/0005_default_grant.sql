-- SPDX-License-Identifier: Apache-2.0

-- The default-ONCE bookkeeping table + the cross-service grants the default-grant
-- writer (internal/authz/store.EnsureDefaultGrant) needs to be callable from bootstrap, registry,
-- and org's OWN transactions (never a raw INSERT into authz.tuple from another service's code —
-- store.Grant/EnsureDefaultGrant is the audited write path, called on the CALLER's own pgx.Tx,
-- exactly like store.Grant/Revoke's existing doc comment already describes for "org creating a
-- position"). default_grant records every (company_id, module_key) pair EVER defaulted — the
-- writer's ON CONFLICT DO NOTHING claim against this table (never re-checked afterward) is what
-- makes a deliberately-removed grant stay removed across any later converger/hook rerun.
CREATE TABLE authz.default_grant (
    company_id  text NOT NULL,
    module_key  text NOT NULL,
    actor       text NOT NULL,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (company_id, module_key)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON authz.default_grant TO kiban_authz;

-- kiban_registry (registry's Seed/SetEnabled hook) and kiban_org (org's company-creation
-- hook) both call store.EnsureDefaultGrant on THEIR OWN pool/role — never a second hop
-- through authz's HTTP surface for this internal, transactional, audited write. kiban_registry
-- already has USAGE ON SCHEMA authz (migrations/authz/0004_registry_fragment_grant.sql); kiban_org
-- gets it fresh here. Both get SELECT+INSERT on the same three tables store.Grant/EnsureDefaultGrant
-- touch (never UPDATE/DELETE — the grant path only ever inserts a tuple/ledger row or claims a
-- default_grant row; revocation is a separate, human-triggered surface).
GRANT USAGE ON SCHEMA authz TO kiban_org;
GRANT SELECT, INSERT ON authz.tuple, authz.grant_ledger, authz.default_grant TO kiban_registry, kiban_org;

---- create above / drop below ----

REVOKE SELECT, INSERT ON authz.tuple, authz.grant_ledger, authz.default_grant FROM kiban_registry, kiban_org;
REVOKE USAGE ON SCHEMA authz FROM kiban_org;
REVOKE ALL ON authz.default_grant FROM kiban_authz;
DROP TABLE authz.default_grant;
