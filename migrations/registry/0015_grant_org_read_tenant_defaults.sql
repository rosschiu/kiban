-- SPDX-License-Identifier: Apache-2.0

-- org's assign-NOW/end-NOW "today" is the calendar date in `platform.tenant_defaults.timezone`,
-- read inside org's own transaction on org's own role — same read-only
-- cross-schema shape as 0007 (kiban_org already has USAGE on schema platform from there).
GRANT SELECT ON platform.tenant_defaults TO kiban_org;

---- create above / drop below ----

REVOKE SELECT ON platform.tenant_defaults FROM kiban_org;
