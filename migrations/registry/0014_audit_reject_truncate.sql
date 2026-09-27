-- SPDX-License-Identifier: Apache-2.0

-- Audit append-only, storage level, now also against TRUNCATE: the row-level
-- `*_append_only` trigger (0004) never fires for TRUNCATE, so the table owner (`kiban`, which
-- migrations and bootstrap run as) could empty an audit table silently. A BEFORE TRUNCATE
-- statement trigger reusing the same `audit.reject_mutation()` closes that.
--
-- `audit.reject_mutation()` is OWNED BY THIS TREE (registry/0004 created it); identity, org and
-- authz re-create it with CREATE OR REPLACE only so their trees parse standalone (sqlc) and
-- apply in any order. The same idempotent re-create here means a tree whose 0004
-- down section already dropped the function is repaired the moment this migration applies —
-- no tree's down section drops the function again (each tree's down section drops its trigger
-- only).
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER registry__events_reject_truncate
    BEFORE TRUNCATE ON audit.registry__events
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

---- create above / drop below ----

DROP TRIGGER registry__events_reject_truncate ON audit.registry__events;
