-- SPDX-License-Identifier: Apache-2.0

-- identity.platform_role is retired: the authz tuple `system:platform#superadmin @ user:<kcSub>`
-- is the platform role's only record (migrations/authz/0010 backfilled it). Refuse to drop while
-- any holder still lacks its tuple — that means authz's migrations have not run yet (apply them
-- first; infra/migrate-entrypoint.sh orders authz before identity).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.platform_role pr
        JOIN identity.user_account ua ON ua.id = pr.user_id
        WHERE pr.role = 'kiban-superadmin'
          AND NOT EXISTS (
            SELECT 1 FROM authz.tuple t
            WHERE t.object_type = 'system' AND t.object_id = 'platform' AND t.relation = 'superadmin'
              AND t.subject_type = 'user' AND t.subject_id = ua.kc_sub AND t.subject_relation = ''
          )
    ) THEN
        RAISE EXCEPTION 'identity.platform_role holds a superadmin with no system:platform#superadmin tuple — apply migrations/authz (0010_platform_role_backfill) first';
    END IF;
END $$;

DROP TABLE identity.platform_role;

---- create above / drop below ----

CREATE TABLE identity.platform_role (
    user_id    uuid NOT NULL REFERENCES identity.user_account (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('kiban-superadmin')),
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by text NOT NULL,
    PRIMARY KEY (user_id, role)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity.platform_role TO kiban_identity;
