-- SPDX-License-Identifier: Apache-2.0

-- BEFORE TRUNCATE statement trigger on the org audit table — the row-level
-- append-only trigger (0003) never fires for TRUNCATE. Same pattern as
-- migrations/registry/0014_audit_reject_truncate.sql.
--
-- `audit.reject_mutation()` is owned by registry's tree (registry/0004); the CREATE OR REPLACE
-- here only keeps this tree self-contained (sqlc parses migrations/org alone) and
-- order-independent. The down section drops the trigger only — never the shared function.
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER org__events_reject_truncate
    BEFORE TRUNCATE ON audit.org__events
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

---- create above / drop below ----

DROP TRIGGER org__events_reject_truncate ON audit.org__events;
