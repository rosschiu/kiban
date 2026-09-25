-- SPDX-License-Identifier: Apache-2.0

-- Published read contract: the ONLY way other services read identity data.
-- Versioned by migration; base tables (identity.user_account etc.) stay ungranted to other
-- service roles. org's member directory joins this view; authz reads it for effective-access.
-- kiban_registry is not granted — the registry has no reason to read user rows.
CREATE VIEW identity.user_read_v AS
SELECT id, kc_sub, email, preferred_username, lifecycle
FROM identity.user_account;

GRANT SELECT ON identity.user_read_v TO kiban_org, kiban_authz;

---- create above / drop below ----

REVOKE SELECT ON identity.user_read_v FROM kiban_org, kiban_authz;
DROP VIEW identity.user_read_v;
