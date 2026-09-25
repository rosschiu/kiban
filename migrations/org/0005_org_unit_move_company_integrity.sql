-- SPDX-License-Identifier: Apache-2.0

-- Cross-company integrity must survive org-unit MOVES. Migration
-- 0004_cross_company_constraints.sql's triggers only fire on org.position / org.position_assignment
-- writes; nothing stopped re-parenting a subtree under ANOTHER company from dragging its
-- positions across the company boundary (UpdateOrgUnit, internal/org/store.go, only checks for
-- cycles). This migration closes that gap at the DB layer with a BEFORE UPDATE OF parent_id
-- trigger on org.org_unit — same style as 0002's org.validate_member_company() /
-- 0004's org.validate_position_company(): a plain CHECK can't walk the org_unit tree, so a
-- trigger does the equivalent validation at update time.
--
-- Trigger column list is `OF parent_id` only, deliberately omitting is_active: type_key is
-- immutable after creation (0002/org_unit_type comment; UpdateOrgUnit's query has no type_key
-- column) and is_company is a property of org_unit_type, not of a given org_unit row, so no
-- update to an existing row can ever change which node resolves as "the" company root — is_active
-- cannot affect company-typing.
--
-- Pre-flight: same discipline as 0002/0004 — dev/live DBs may already hold fixture junk that
-- violates the invariant this migration is about to enforce. Fail loudly, never silently fix.
DO $$
DECLARE
    bad_positions integer;
BEGIN
    WITH RECURSIVE roots AS (
        SELECT id, id AS root_id FROM org.org_unit WHERE parent_id IS NULL
        UNION ALL
        SELECT u.id, r.root_id FROM org.org_unit u JOIN roots r ON u.parent_id = r.id
    )
    SELECT count(*) INTO bad_positions
    FROM org.position p
    JOIN roots r ON r.id = p.org_unit_id
    WHERE p.company_id IS DISTINCT FROM r.root_id;

    IF bad_positions > 0 THEN
        RAISE EXCEPTION 'pre-flight: % org.position row(s) whose org_unit_id''s resolved root company differs from company_id — clean this data before applying this migration; it refuses to apply until this count is 0', bad_positions;
    END IF;
END $$;

-- validate_org_unit_move_company: when an org_unit's parent_id actually changes AND that changes
-- the unit's resolved root company (the topmost ancestor, parent_id IS NULL — the company, per
-- 0002's org_unit comment convention), reject the move if the moved subtree (the unit itself plus
-- every descendant) still holds any org.position row whose company_id is not the NEW root
-- company. An empty subtree (no positions anywhere inside it) may re-home across companies
-- freely — positions are the blocker, not the org-unit shape alone.
CREATE FUNCTION org.validate_org_unit_move_company() RETURNS trigger AS $$
DECLARE
    old_root uuid;
    new_root uuid;
    blocked  boolean;
BEGIN
    IF OLD.parent_id IS NOT DISTINCT FROM NEW.parent_id THEN
        RETURN NEW;
    END IF;

    -- old_root: this row's resolved root BEFORE the move. Safe to read via org.org_unit here —
    -- this is a BEFORE trigger, so the table still holds the pre-update row for NEW.id.
    WITH RECURSIVE chain AS (
        SELECT id, parent_id FROM org.org_unit WHERE id = NEW.id
        UNION ALL
        SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
    )
    SELECT id INTO old_root FROM chain WHERE parent_id IS NULL;

    -- new_root: resolved root AFTER the move — walk up from the NEW parent (an unaffected row),
    -- or NEW.id itself if this move makes the unit a root.
    IF NEW.parent_id IS NULL THEN
        new_root := NEW.id;
    ELSE
        WITH RECURSIVE chain AS (
            SELECT id, parent_id FROM org.org_unit WHERE id = NEW.parent_id
            UNION ALL
            SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
        )
        SELECT id INTO new_root FROM chain WHERE parent_id IS NULL;
    END IF;

    IF old_root IS NOT DISTINCT FROM new_root THEN
        RETURN NEW; -- same resolved company: always allowed, including plain reordering within it
    END IF;

    WITH RECURSIVE subtree AS (
        SELECT id FROM org.org_unit WHERE id = NEW.id
        UNION ALL
        SELECT u.id FROM org.org_unit u JOIN subtree s ON u.parent_id = s.id
    )
    SELECT EXISTS (
        SELECT 1 FROM org.position p JOIN subtree s ON p.org_unit_id = s.id
        WHERE p.company_id IS DISTINCT FROM new_root
    ) INTO blocked;

    IF blocked THEN
        RAISE EXCEPTION 'org.org_unit % cannot move under a new parent: its subtree still holds position(s) belonging to company % (the pre-move root) — reassign or delete those positions before moving this subtree under company %', NEW.id, old_root, new_root
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER org_unit_move_must_preserve_company
    BEFORE UPDATE OF parent_id ON org.org_unit
    FOR EACH ROW EXECUTE FUNCTION org.validate_org_unit_move_company();

---- create above / drop below ----

DROP TRIGGER org_unit_move_must_preserve_company ON org.org_unit;
DROP FUNCTION org.validate_org_unit_move_company();
