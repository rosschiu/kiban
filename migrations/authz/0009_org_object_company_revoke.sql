-- SPDX-License-Identifier: Apache-2.0

-- Extend the SECURITY DEFINER revocation function's allowed tuple shapes (migrations/authz/0006,
-- 0007, 0008) with the org object company anchors: org writes `position:<id>#company @
-- company:<companyId>` and `group:<id>#company @ company:<companyId>` when a position/group is
-- created and must revoke the position one when the position is deleted, in the SAME
-- transaction as the row and its audit event (the anchor the authz decision
-- layer binds a position/group object check to the request's company through). CREATE OR
-- REPLACE keeps name/signature/ownership/EXECUTE grant exactly as 0006 left them; only the
-- hard-coded shape check widens with two more allowed combinations:
--   5. object_type='position', relation='company', subject_type='company', subject_relation=''
--   6. object_type='group',    relation='company', subject_type='company', subject_relation=''
-- Any other combination still raises (fail closed) exactly as before.
CREATE OR REPLACE FUNCTION authz.revoke_position_or_member_tuple(
    p_actor text,
    p_correlation_id text,
    p_object_type text,
    p_object_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_subject_relation text
) RETURNS void AS $$
BEGIN
    IF NOT (
        (p_object_type = 'position' AND p_relation = 'holder'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
        OR
        (p_object_type = 'member' AND p_relation = 'mapped_user'
            AND p_subject_type = 'user' AND p_subject_relation = '')
        OR
        (p_object_type = 'group' AND p_relation = 'member'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
        OR
        (p_object_type = 'company' AND p_relation = 'member'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
        OR
        (p_object_type = 'position' AND p_relation = 'company'
            AND p_subject_type = 'company' AND p_subject_relation = '')
        OR
        (p_object_type = 'group' AND p_relation = 'company'
            AND p_subject_type = 'company' AND p_subject_relation = '')
    ) THEN
        RAISE EXCEPTION
            'authz.revoke_position_or_member_tuple: tuple shape not permitted (object_type=%, relation=%, subject_type=%, subject_relation=%)',
            p_object_type, p_relation, p_subject_type, p_subject_relation
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    DELETE FROM authz.tuple
    WHERE object_type = p_object_type AND object_id = p_object_id AND relation = p_relation
      AND subject_type = p_subject_type AND subject_id = p_subject_id AND subject_relation = p_subject_relation;

    INSERT INTO authz.grant_ledger
        (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
    VALUES (p_actor, p_object_type, p_object_id, p_relation, p_subject_type, p_subject_id, p_subject_relation,
            'revoke', NULLIF(p_correlation_id, ''));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = authz, pg_temp;

---- create above / drop below ----

-- Roll back to the position/member/group/company-member shape — restores migrations/authz/0008's
-- function body verbatim.
CREATE OR REPLACE FUNCTION authz.revoke_position_or_member_tuple(
    p_actor text,
    p_correlation_id text,
    p_object_type text,
    p_object_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_subject_relation text
) RETURNS void AS $$
BEGIN
    IF NOT (
        (p_object_type = 'position' AND p_relation = 'holder'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
        OR
        (p_object_type = 'member' AND p_relation = 'mapped_user'
            AND p_subject_type = 'user' AND p_subject_relation = '')
        OR
        (p_object_type = 'group' AND p_relation = 'member'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
        OR
        (p_object_type = 'company' AND p_relation = 'member'
            AND p_subject_type = 'member' AND p_subject_relation = 'mapped_user')
    ) THEN
        RAISE EXCEPTION
            'authz.revoke_position_or_member_tuple: tuple shape not permitted (object_type=%, relation=%, subject_type=%, subject_relation=%)',
            p_object_type, p_relation, p_subject_type, p_subject_relation
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    DELETE FROM authz.tuple
    WHERE object_type = p_object_type AND object_id = p_object_id AND relation = p_relation
      AND subject_type = p_subject_type AND subject_id = p_subject_id AND subject_relation = p_subject_relation;

    INSERT INTO authz.grant_ledger
        (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
    VALUES (p_actor, p_object_type, p_object_id, p_relation, p_subject_type, p_subject_id, p_subject_relation,
            'revoke', NULLIF(p_correlation_id, ''));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = authz, pg_temp;
