-- SPDX-License-Identifier: Apache-2.0

-- One-time backfill: the tuple `system:platform#superadmin @ user:<kcSub>` becomes the ONLY
-- record of the platform role. Every identity.platform_role holder that has no tuple yet gets
-- one, plus the grant_ledger row internal/authz/store.Grant would have written (one per tuple
-- actually inserted — a holder whose tuple bootstrap already projected gets nothing). Runs as
-- the owner role, which can read identity's schema; migrations/identity/0005 drops the table
-- afterwards and refuses to run while any holder still lacks its tuple, so the migrate order
-- (authz before identity — infra/migrate-entrypoint.sh) is enforced by the data, not just by
-- convention. On a fresh database identity's tables do not exist yet at this point: nothing to
-- backfill, skip.
DO $$
BEGIN
    IF to_regclass('identity.platform_role') IS NULL THEN
        RETURN;
    END IF;
    WITH ins AS (
        INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
        SELECT 'system', 'platform', 'superadmin', 'user', ua.kc_sub, ''
        FROM identity.platform_role pr
        JOIN identity.user_account ua ON ua.id = pr.user_id
        WHERE pr.role = 'kiban-superadmin'
        ON CONFLICT DO NOTHING
        RETURNING subject_id
    )
    INSERT INTO authz.grant_ledger
        (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
    SELECT 'migration', 'system', 'platform', 'superadmin', 'user', subject_id, '', 'grant', 'platform-role-backfill'
    FROM ins;
END $$;

---- create above / drop below ----

-- No-op: the backfilled tuples are real grants and stay.
