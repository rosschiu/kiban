-- SPDX-License-Identifier: Apache-2.0

-- NO table-wide DELETE grant on authz.tuple to any service role.
-- kiban_org's runtime role has SELECT+INSERT only on authz.tuple/grant_ledger
-- (migrations/authz/0005_default_grant.sql) — deliberately no DELETE. Org still needs to REVOKE
-- tuples transactionally (assignment end, member unlink) as part of its own business-write
-- transaction. This function, owned by `kiban` (the schema owner — migrations run as this role),
-- runs with the OWNER's privileges when called (SECURITY DEFINER), restricted by a hard-coded
-- shape check to EXACTLY the two tuple families org's assignment/member writes own:
--   1. object_type='position', relation='holder', subject_type='member', subject_relation='mapped_user'
--   2. object_type='member',   relation='mapped_user', subject_type='user', subject_relation=''
-- Any other combination raises an exception — this function can never be used to delete an
-- arbitrary tuple, and is not a general-purpose revoke. It deletes the tuple AND writes the
-- authz.grant_ledger row itself (mirroring internal/authz/store.Revoke's ledger discipline), so
-- kiban_org needs no DELETE grant and no separate ledger-insert carve-out either. kiban_org gets
-- EXECUTE ONLY — never broader schema rights.
CREATE FUNCTION authz.revoke_position_or_member_tuple(
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

GRANT EXECUTE ON FUNCTION authz.revoke_position_or_member_tuple(text, text, text, text, text, text, text, text)
    TO kiban_org;

---- create above / drop below ----

REVOKE EXECUTE ON FUNCTION authz.revoke_position_or_member_tuple(text, text, text, text, text, text, text, text)
    FROM kiban_org;
DROP FUNCTION authz.revoke_position_or_member_tuple(text, text, text, text, text, text, text, text);
