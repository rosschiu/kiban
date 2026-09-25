-- SPDX-License-Identifier: Apache-2.0

-- Org's company-creation hook needs to read which modules are currently
-- installed+enabled (platform.module_installation, registry-owned) to default-grant a brand new
-- company against every one of them. Read-only: org never writes registry's own tables.
GRANT USAGE ON SCHEMA platform TO kiban_org;
GRANT SELECT ON platform.module_installation TO kiban_org;

---- create above / drop below ----

REVOKE SELECT ON platform.module_installation FROM kiban_org;
REVOKE USAGE ON SCHEMA platform FROM kiban_org;
