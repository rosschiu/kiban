-- SPDX-License-Identifier: Apache-2.0

-- Close the concurrency bypass. Both 0004's cross-company
-- triggers and 0005's unit-move trigger validate against their OWN transaction's MVCC snapshot —
-- two CONCURRENT writers each see a consistent world, pass their own check, and jointly commit an
-- inconsistent one (e.g. a unit-move ∥ position-create can leave a
-- position whose declared company differs from its actual resolved root; an A→B ∥ B→A sibling
-- swap can commit a parent cycle neither side's own snapshot could see).
--
-- ONE transaction-scoped advisory lock (rather than SERIALIZABLE or SELECT FOR UPDATE on ancestor
-- chains) serializes every
-- org-structure WRITE (org_unit parent changes, position creates/updates, assignment creates).
-- Writer-only — this never blocks a read. Held for milliseconds per statement.
CREATE FUNCTION org.lock_org_tree() RETURNS void AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('kiban.org_tree'));
END;
$$ LANGUAGE plpgsql;

-- org.org_unit: BEFORE ROW (not statement) because the cycle re-validation below needs NEW.id /
-- NEW.parent_id per row. Acquires the lock FIRST, then — only when parent_id is actually
-- changing — walks NEW's new ancestor chain (now reading a lock-protected snapshot: no other
-- writer can be mid-move) and RAISEs if NEW.id is revisited, i.e. the move would create a cycle.
-- This is the DB-layer backstop against direct SQL writes to org.org_unit.parent_id that skip
-- store.go's own subtree walk entirely; store.go's UpdateOrgUnit performs the equivalent walk
-- for the store-level 422 UX, also lock-protected. Trigger name is deliberately "org_unit_lock_..." — Postgres fires same-timing
-- (BEFORE ROW) triggers on one table in NAME order, and "l" < "m" sorts this trigger ahead of
-- 0005's "org_unit_move_must_preserve_company", so the lock is held before that trigger's own
-- company check runs (0005's trigger body is unchanged — it just now runs lock-protected).
CREATE FUNCTION org.org_unit_lock_and_check_cycle() RETURNS trigger AS $$
DECLARE
    cur     uuid;
    visited uuid[] := ARRAY[]::uuid[];
BEGIN
    PERFORM org.lock_org_tree();

    IF TG_OP = 'UPDATE' AND OLD.parent_id IS NOT DISTINCT FROM NEW.parent_id THEN
        RETURN NEW;
    END IF;

    cur := NEW.parent_id;
    WHILE cur IS NOT NULL LOOP
        IF cur = NEW.id THEN
            RAISE EXCEPTION 'org.org_unit % cannot move under this parent chain: % is already an ancestor of the candidate parent, the move would create a cycle', NEW.id, NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
        visited := visited || cur;
        SELECT parent_id INTO cur FROM org.org_unit WHERE id = cur;
        IF cur = ANY(visited) THEN
            -- Defensive only: a pre-existing cycle elsewhere in the chain, unreachable in
            -- practice given this trigger plus 0002's self-parent CHECK, but this avoids an
            -- infinite loop if one is ever somehow present.
            EXIT;
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER org_unit_lock_before_move
    BEFORE INSERT OR UPDATE OF parent_id ON org.org_unit
    FOR EACH ROW EXECUTE FUNCTION org.org_unit_lock_and_check_cycle();

-- org.position / org.position_assignment: BEFORE STATEMENT, not ROW — these triggers need no
-- per-row NEW data, only the lock held before the existing 0004 row-level validation triggers
-- (position_org_unit_must_be_under_company / assignment_member_must_match_position_company) run.
-- Postgres always fires BEFORE STATEMENT triggers before BEFORE ROW triggers for the same event
-- on the same table regardless of name, so this ordering holds without relying on trigger-name
-- sort — and a statement trigger fires once per statement (cheaper than once per row) for the
-- same effect, since the lock is a single transaction-scoped acquisition either way.
CREATE FUNCTION org.position_lock_org_tree() RETURNS trigger AS $$
BEGIN
    PERFORM org.lock_org_tree();
    RETURN NULL; -- ignored for a statement-level trigger
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER position_lock_org_tree
    BEFORE INSERT OR UPDATE ON org.position
    FOR EACH STATEMENT EXECUTE FUNCTION org.position_lock_org_tree();

CREATE FUNCTION org.assignment_lock_org_tree() RETURNS trigger AS $$
BEGIN
    PERFORM org.lock_org_tree();
    RETURN NULL; -- ignored for a statement-level trigger
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER assignment_lock_org_tree
    BEFORE INSERT OR UPDATE ON org.position_assignment
    FOR EACH STATEMENT EXECUTE FUNCTION org.assignment_lock_org_tree();

---- create above / drop below ----

DROP TRIGGER assignment_lock_org_tree ON org.position_assignment;
DROP FUNCTION org.assignment_lock_org_tree();
DROP TRIGGER position_lock_org_tree ON org.position;
DROP FUNCTION org.position_lock_org_tree();
DROP TRIGGER org_unit_lock_before_move ON org.org_unit;
DROP FUNCTION org.org_unit_lock_and_check_cycle();
DROP FUNCTION org.lock_org_tree();
