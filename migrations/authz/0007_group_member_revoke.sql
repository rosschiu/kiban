-- SPDX-License-Identifier: Apache-2.0

-- Extend the SECURITY DEFINER revocation function's allowed tuple shapes (migrations/authz/0006)
-- with the `group:*#member` family (org's group_member single-writer invariant needs the SAME
-- transactional-revoke seam as position/member — no table-wide DELETE grant on authz.tuple,
-- ever). CREATE OR REPLACE keeps the function's
-- name/signature/ownership/EXECUTE grant exactly as migrations/authz/0006 left them (still owned
-- by `kiban`, still SECURITY DEFINER, still kiban_org EXECUTE-only) — only the hard-coded shape
-- check widens to a third allowed combination:
--   3. object_type='group', relation='member', subject_type='member', subject_relation='mapped_user'
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

-- Roll back to the position/member-only shape — restores migrations/authz/0006's
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
