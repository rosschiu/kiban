-- SPDX-License-Identifier: Apache-2.0

-- company_id is immutable after insert on org.position AND org.member (otherwise
-- the `kiban_org` runtime role could reverse-update an assigned position's or member's
-- company_id via direct SQL, since 0004's assignment trigger only fires on
-- org.position_assignment writes and never revalidates existing assignments when a position or
-- member is later moved to another company). No application query ever updates company_id after
-- insert (internal/org/queries.sql's UpdatePosition/UpdateMember never touch it) — "moving" a
-- position or member to another company is not a domain operation, so instead of building
-- assignment-revalidation machinery for a transition that doesn't exist, make the column say
-- what the domain says: company_id is immutable. Comparing OLD to NEW needs no snapshot read, so
-- this is concurrency-safe by construction — no 0006 advisory-lock involvement needed.
CREATE FUNCTION org.reject_company_id_change() RETURNS trigger AS $$
BEGIN
    IF NEW.company_id IS DISTINCT FROM OLD.company_id THEN
        RAISE EXCEPTION '% company_id is immutable after insert (was %, attempted %)',
            TG_TABLE_NAME, OLD.company_id, NEW.company_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER position_company_id_immutable
    BEFORE UPDATE OF company_id ON org.position
    FOR EACH ROW EXECUTE FUNCTION org.reject_company_id_change();

CREATE TRIGGER member_company_id_immutable
    BEFORE UPDATE OF company_id ON org.member
    FOR EACH ROW EXECUTE FUNCTION org.reject_company_id_change();

---- create above / drop below ----

DROP TRIGGER member_company_id_immutable ON org.member;
DROP TRIGGER position_company_id_immutable ON org.position;
DROP FUNCTION org.reject_company_id_change();
