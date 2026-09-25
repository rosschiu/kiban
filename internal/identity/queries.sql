-- SPDX-License-Identifier: Apache-2.0

-- sqlc-generated queries for the identity service.

-- name: UpsertUserAccount :one
-- Resolve-or-create: identity fields ONLY (never touches user_login_observation).
-- Idempotent: calling twice with the same kc_sub returns the same row (id stable), refreshing
-- email/preferred_username from the latest validated bearer claims.
INSERT INTO identity.user_account (kc_sub, email, preferred_username)
VALUES ($1, $2, $3)
ON CONFLICT (kc_sub) DO UPDATE SET
    email = EXCLUDED.email,
    preferred_username = EXCLUDED.preferred_username,
    updated_at = now()
RETURNING *;

-- name: GetUserAccountByKcSub :one
SELECT * FROM identity.user_account WHERE kc_sub = $1;

-- name: GetUserAccountByID :one
SELECT * FROM identity.user_account WHERE id = $1;

-- name: GetGlobalMfaPolicy :one
SELECT * FROM identity.mfa_policy WHERE scope = 'global';

-- name: GetUserMfaPolicy :one
SELECT * FROM identity.mfa_policy WHERE scope = 'user' AND subject_id = $1;

-- name: SetGlobalMfaPolicy :exec
UPDATE identity.mfa_policy
SET required = $1, method = $2, updated_at = now()
WHERE scope = 'global';

-- name: UpsertUserMfaPolicy :exec
INSERT INTO identity.mfa_policy (scope, subject_id, required, method)
VALUES ('user', $1, $2, $3)
ON CONFLICT (subject_id) WHERE scope = 'user' DO UPDATE SET
    required = EXCLUDED.required,
    method = EXCLUDED.method,
    updated_at = now();

-- name: DeleteUserMfaPolicy :execrows
DELETE FROM identity.mfa_policy WHERE scope = 'user' AND subject_id = $1;

-- name: ListUserAccountsWithMfaPolicy :many
-- Drives SyncMfaPolicy: every user plus their effective policy inputs (global row's
-- required/method come back on every call the store layers in Go, not here).
SELECT ua.id, ua.kc_sub, mp.required, mp.method
FROM identity.user_account ua
LEFT JOIN identity.mfa_policy mp ON mp.scope = 'user' AND mp.subject_id = ua.id
ORDER BY ua.id;
