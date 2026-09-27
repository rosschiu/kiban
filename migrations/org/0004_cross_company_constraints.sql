-- SPDX-License-Identifier: Apache-2.0

-- Cross-company position/assignment constraints.
-- The database must refuse cross-company facts: a position's org_unit must sit beneath the
-- position's own company_id, and a position_assignment's member must belong to that same
-- company. Same style as migrations/org/0002_org_tables.sql's
-- org.validate_member_company()/member_company_must_be_company_typed trigger (a plain CHECK
-- can't join across tables or walk the org_unit tree, so triggers do the equivalent validation
-- at insert/update time).
--
-- Pre-flight: existing DBs may hold fixture junk that already violates
-- these rules. This migration must fail LOUDLY on existing
-- violations, never silently delete or "fix" data — cleaning production-ish data is a human
-- decision. Run this check before creating anything below.
DO $$
DECLARE
    bad_positions   integer;
    bad_assignments integer;
BEGIN
    SELECT count(*) INTO bad_positions
    FROM org.position p
    WHERE NOT EXISTS (
        WITH RECURSIVE chain AS (
            SELECT id, parent_id FROM org.org_unit WHERE id = p.org_unit_id
            UNION ALL
            SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
        )
        SELECT 1 FROM chain WHERE id = p.company_id
    );

    SELECT count(*) INTO bad_assignments
    FROM org.position_assignment pa
    JOIN org.position p ON p.id = pa.position_id
    JOIN org.member m ON m.id = pa.member_id
    WHERE p.company_id IS DISTINCT FROM m.company_id;

    IF bad_positions > 0 OR bad_assignments > 0 THEN
        RAISE EXCEPTION 'pre-flight: % org.position row(s) whose org_unit_id does not sit beneath company_id, % org.position_assignment row(s) whose member.company_id does not equal the position''s company_id — clean this data before applying this migration; it refuses to apply until both counts are 0', bad_positions, bad_assignments;
    END IF;
END $$;

-- validate_position_company: company_id must be a company-typed org_unit (same check as
-- org.validate_member_company()), AND org_unit_id must resolve upward through parent_id to
-- company_id (org_unit_id itself counts, so a position may sit directly at the company root).
CREATE FUNCTION org.validate_position_company() RETURNS trigger AS $$
DECLARE
    company_typed  boolean;
    under_company  boolean;
BEGIN
    SELECT ut.is_company INTO company_typed
    FROM org.org_unit u JOIN org.org_unit_type ut ON ut.key = u.type_key
    WHERE u.id = NEW.company_id;

    IF company_typed IS NOT TRUE THEN
        RAISE EXCEPTION 'org.position.company_id must reference a company-typed org_unit (got %)', NEW.company_id
            USING ERRCODE = 'check_violation';
    END IF;

    WITH RECURSIVE chain AS (
        SELECT id, parent_id FROM org.org_unit WHERE id = NEW.org_unit_id
        UNION ALL
        SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
    )
    SELECT EXISTS (SELECT 1 FROM chain WHERE id = NEW.company_id) INTO under_company;

    IF NOT under_company THEN
        RAISE EXCEPTION 'org.position.org_unit_id (%) must sit beneath org.position.company_id (%) in the org_unit tree', NEW.org_unit_id, NEW.company_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER position_org_unit_must_be_under_company
    BEFORE INSERT OR UPDATE OF company_id, org_unit_id ON org.position
    FOR EACH ROW EXECUTE FUNCTION org.validate_position_company();

-- validate_assignment_company: the assigned member's company must equal the position's company —
-- the DB-layer backstop for the store-level check (internal/org/store.go).
CREATE FUNCTION org.validate_assignment_company() RETURNS trigger AS $$
DECLARE
    pos_company uuid;
    mem_company uuid;
BEGIN
    SELECT company_id INTO pos_company FROM org.position WHERE id = NEW.position_id;
    SELECT company_id INTO mem_company FROM org.member WHERE id = NEW.member_id;

    IF pos_company IS DISTINCT FROM mem_company THEN
        RAISE EXCEPTION 'org.position_assignment: member % (company %) does not belong to position %''s company (%)',
            NEW.member_id, mem_company, NEW.position_id, pos_company
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER assignment_member_must_match_position_company
    BEFORE INSERT OR UPDATE OF position_id, member_id ON org.position_assignment
    FOR EACH ROW EXECUTE FUNCTION org.validate_assignment_company();

---- create above / drop below ----

DROP TRIGGER assignment_member_must_match_position_company ON org.position_assignment;
DROP FUNCTION org.validate_assignment_company();
DROP TRIGGER position_org_unit_must_be_under_company ON org.position;
DROP FUNCTION org.validate_position_company();
