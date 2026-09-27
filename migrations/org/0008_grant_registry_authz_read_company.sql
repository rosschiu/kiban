-- SPDX-License-Identifier: Apache-2.0

-- Registry's Seed/SetEnabled hook and bootstrap's backfill converge step
-- (which reuses registry's own runtime pool/role to read companies — see
-- internal/bootstrap/seed.go) both need to enumerate ACTIVE companies (org.org_unit rows whose
-- type is org.org_unit_type.is_company = true) to know which company_module pairs to default-
-- grant. kiban_authz is not granted this read (checks against authz's bookkeeping tables
-- run as the migration owner, not a runtime role, so no grant is needed there) — this
-- migration grants ONLY kiban_registry (the one runtime role that actually queries org.org_unit
-- in application code); bootstrap's reuse of registry's pool means no separate grant is needed
-- for a bootstrap-specific role.
GRANT USAGE ON SCHEMA org TO kiban_registry;
GRANT SELECT ON org.org_unit, org.org_unit_type TO kiban_registry;

---- create above / drop below ----

REVOKE SELECT ON org.org_unit, org.org_unit_type FROM kiban_registry;
REVOKE USAGE ON SCHEMA org FROM kiban_registry;
