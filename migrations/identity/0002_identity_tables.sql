-- SPDX-License-Identifier: Apache-2.0

-- Identity tables.
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TABLE identity.user_account (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kc_sub              text NOT NULL UNIQUE,
    email               text,
    preferred_username  text,
    lifecycle           text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'disabled')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Login observation lives in its own table so the identity upsert (resolve-or-create)
-- never touches it, and observing a login never touches identity fields.
CREATE TABLE identity.user_login_observation (
    user_id       uuid PRIMARY KEY REFERENCES identity.user_account (id) ON DELETE CASCADE,
    last_login_at timestamptz,
    last_login_ip text
);

CREATE TABLE identity.platform_role (
    user_id    uuid NOT NULL REFERENCES identity.user_account (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('kiban-superadmin')),
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by text NOT NULL,
    PRIMARY KEY (user_id, role)
);

-- MFA policy layering (no company scope yet):
-- a single global row plus optional per-user overrides; user scope always wins (single global
-- individual exception model — there is exactly one override mechanism, keyed on
-- the user, not a per-company sentinel).
CREATE TABLE identity.mfa_policy (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope       text NOT NULL CHECK (scope IN ('global', 'user')),
    subject_id  uuid REFERENCES identity.user_account (id) ON DELETE CASCADE,
    required    boolean NOT NULL,
    method      text CHECK (method IS NULL OR method IN ('otp', 'passkey', 'otp_or_passkey')),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope = 'global' AND subject_id IS NULL) OR (scope = 'user' AND subject_id IS NOT NULL))
);

-- Exactly one global row; at most one override row per user.
CREATE UNIQUE INDEX mfa_policy_global_singleton ON identity.mfa_policy (scope) WHERE scope = 'global';
CREATE UNIQUE INDEX mfa_policy_user_unique ON identity.mfa_policy (subject_id) WHERE scope = 'user';

-- Seed the global policy row (required=false — MFA off by default until an operator sets it).
INSERT INTO identity.mfa_policy (scope, subject_id, required, method) VALUES ('global', NULL, false, NULL);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    identity.user_account,
    identity.user_login_observation,
    identity.platform_role,
    identity.mfa_policy
TO kiban_identity;

---- create above / drop below ----

REVOKE ALL ON
    identity.user_account,
    identity.user_login_observation,
    identity.platform_role,
    identity.mfa_policy
FROM kiban_identity;
DROP TABLE identity.mfa_policy;
DROP TABLE identity.platform_role;
DROP TABLE identity.user_login_observation;
DROP TABLE identity.user_account;
