// SPDX-License-Identifier: Apache-2.0

// Package identity implements the identity service: canonical Keycloak-subject-keyed user
// records (resolve-or-create), login observation (kept in its own table), and the MFA policy
// layering synced to Keycloak user attributes. The platform role is NOT here: its one record is
// authz's `system:platform#superadmin` tuple (internal/authz/store).
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/pgconv"
)

// Store is the identity service's data access layer: a pgx pool plus the sqlc-generated
// Queries built from it.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an already-connected pool (the caller owns its lifecycle: connect with the
// service's own kiban_identity credentials).
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool returns the underlying pool (used by http.go for the /ready liveness check and by
// callers that need their own transaction, e.g. audited mutations).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself (no
// runtime DDL, ever; migrations are applied out-of-band by `make migrate-identity`, as the
// kiban owner role).
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_identity`).Scan(&version)
	if err != nil {
		return fmt.Errorf(
			"identity: migrations not applied (run `make migrate-identity` against this database first): %w",
			err,
		)
	}
	if version <= 0 {
		return errors.New("identity: migrations table present but at version 0 — run `make migrate-identity`")
	}
	return nil
}

// User is the API-facing shape of an identity.user_account row (uuid.UUID instead of
// pgtype.UUID; string instead of pgtype.Timestamptz — keeps sqlc's generated types out of the
// package's public surface).
type User struct {
	ID                uuid.UUID
	KcSub             string
	Email             string
	PreferredUsername string
	Lifecycle         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func userFromRow(r IdentityUserAccount) User {
	return User{
		ID:                uuidFromPg(r.ID),
		KcSub:             r.KcSub,
		Email:             pgconv.DerefStr(r.Email),
		PreferredUsername: pgconv.DerefStr(r.PreferredUsername),
		Lifecycle:         r.Lifecycle,
		CreatedAt:         r.CreatedAt.Time,
		UpdatedAt:         r.UpdatedAt.Time,
	}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// ResolveOrCreate is the bodyless self-sync: identity comes only from the validated bearer
// (kcSub/email/preferredUsername are claims already extracted by the HTTP layer — never a
// request body). It touches identity.user_account ONLY (never user_login_observation), and is
// idempotent: calling it twice with the same kcSub returns the
// same row id.
func (s *Store) ResolveOrCreate(ctx context.Context, kcSub, email, preferredUsername string) (User, error) {
	q := New(s.pool)
	row, err := q.UpsertUserAccount(ctx, UpsertUserAccountParams{
		KcSub:             kcSub,
		Email:             pgconv.StrOrNil(email),
		PreferredUsername: pgconv.StrOrNil(preferredUsername),
	})
	if err != nil {
		return User{}, fmt.Errorf("identity: resolve-or-create: %w", err)
	}
	return userFromRow(row), nil
}

// ErrUserNotFound is returned when a kc_sub or user id has no identity.user_account row.
var ErrUserNotFound = errors.New("identity: user not found")

// GetUserByKcSub looks up a user by Keycloak subject.
func (s *Store) GetUserByKcSub(ctx context.Context, kcSub string) (User, error) {
	q := New(s.pool)
	row, err := q.GetUserAccountByKcSub(ctx, kcSub)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("identity: get user by kc_sub: %w", err)
	}
	return userFromRow(row), nil
}

// GetUserByID looks up a user by internal id.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	q := New(s.pool)
	row, err := q.GetUserAccountByID(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("identity: get user by id: %w", err)
	}
	return userFromRow(row), nil
}

// MfaPolicy is the effective (or scoped) MFA policy shape.
type MfaPolicy struct {
	Required bool
	Method   string
}

// EffectivePolicy resolves the MFA layering for userID: user-scope overrides global (a single
// global policy plus individual per-user exceptions; SetUserPolicy guarantees an override never
// ranks below the global policy). Falls back to the global row when the user has no override;
// ErrUserNotFound for an unknown user id.
func (s *Store) EffectivePolicy(ctx context.Context, userID uuid.UUID) (MfaPolicy, error) {
	q := New(s.pool)
	userRow, err := q.GetUserMfaPolicy(ctx, pgFromUUID(userID))
	if err == nil {
		return MfaPolicy{Required: userRow.Required, Method: pgconv.DerefStr(userRow.Method)}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return MfaPolicy{}, fmt.Errorf("identity: get user mfa policy: %w", err)
	}
	if err := requireUser(ctx, q, userID); err != nil {
		return MfaPolicy{}, err
	}

	globalRow, err := q.GetGlobalMfaPolicy(ctx)
	if err != nil {
		return MfaPolicy{}, fmt.Errorf("identity: get global mfa policy: %w", err)
	}
	return MfaPolicy{Required: globalRow.Required, Method: pgconv.DerefStr(globalRow.Method)}, nil
}

// GetGlobalPolicy returns the global MFA policy row directly (no layering).
func (s *Store) GetGlobalPolicy(ctx context.Context) (MfaPolicy, error) {
	q := New(s.pool)
	row, err := q.GetGlobalMfaPolicy(ctx)
	if err != nil {
		return MfaPolicy{}, fmt.Errorf("identity: get global mfa policy: %w", err)
	}
	return MfaPolicy{Required: row.Required, Method: pgconv.DerefStr(row.Method)}, nil
}

// ErrMfaMethodUnenforceable is returned by SetGlobalPolicy/SetUserPolicy when required=true is
// paired with an empty or unrecognized method. Rejecting it here, at write time, means the
// ambiguous policy never reaches the database at all; sync's own refusal (requiredModeFor in
// sync.go) stays as a defense-in-depth backstop for any row that predates this check.
var ErrMfaMethodUnenforceable = errors.New("identity: required mfa policy needs an enforceable method (one of otp, passkey, otp_or_passkey)")

// isEnforceableMfaMethod lists the exact method values requiredModeFor (sync.go) can map to a
// required_mode the installed Keycloak authenticator understands — kept in sync with that
// mapping table without importing sync.go's own vocabulary.
func isEnforceableMfaMethod(method string) bool {
	switch method {
	case "otp", "passkey", "otp_or_passkey":
		return true
	default:
		return false
	}
}

// SetGlobalPolicy updates the single global MFA policy row, auditing in the SAME transaction as
// the state change (the tx+auditRecord-callback shape every mutation here uses). An audit
// failure rolls back the policy write (fail closed). required=true with an empty/unenforceable
// method is rejected before any transaction begins.
func (s *Store) SetGlobalPolicy(ctx context.Context, required bool, method string, auditRecord func(ctx context.Context, tx pgx.Tx) error) error {
	if required && !isEnforceableMfaMethod(method) {
		return ErrMfaMethodUnenforceable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	if err := q.SetGlobalMfaPolicy(ctx, SetGlobalMfaPolicyParams{Required: required, Method: pgconv.StrOrNil(method)}); err != nil {
		return fmt.Errorf("identity: set global mfa policy: %w", err)
	}
	if auditRecord != nil {
		if err := auditRecord(ctx, tx); err != nil {
			return fmt.Errorf("identity: audit mutation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("identity: commit tx: %w", err)
	}
	return nil
}

// ErrMfaPolicyWeakerThanGlobal is returned by SetUserPolicy when the override would rank below
// the global policy: a per-user override may only raise the requirement, never lower it.
var ErrMfaPolicyWeakerThanGlobal = errors.New("identity: a user mfa policy override may only raise the requirement above the global policy, not lower it")

// mfaPolicyRank orders policies by strength — none < otp < otp_or_passkey < passkey, the
// required_mode ranking docs/reference/nexus-authz-identity-audit.md (§ login security) carries
// over (passkey outranks OTP; "either" sits between because it admits a passkey). An
// unenforceable required policy ranks as none (SetUserPolicy/SetGlobalPolicy refuse it anyway).
func mfaPolicyRank(p MfaPolicy) int {
	if !p.Required {
		return 0
	}
	switch p.Method {
	case "otp":
		return 1
	case "otp_or_passkey":
		return 2
	case "passkey":
		return 3
	}
	return 0
}

// requireUser is the shared "does this user id exist" check the user-scoped policy methods
// run first, so an unknown id is ErrUserNotFound (404) rather than an FK violation (500) or a
// silent global fallback.
func requireUser(ctx context.Context, q *Queries, userID uuid.UUID) error {
	if _, err := q.GetUserAccountByID(ctx, pgFromUUID(userID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("identity: get user by id: %w", err)
	}
	return nil
}

// SetUserPolicy upserts userID's individual override (the single-exception model: at most one
// override row per user, enforced by the DB's partial unique index), auditing in the same
// transaction. required=true with an empty/unenforceable method is rejected before any
// transaction begins (same rule as SetGlobalPolicy); an override ranking below the global
// policy is ErrMfaPolicyWeakerThanGlobal (an override may only raise); an unknown user id is
// ErrUserNotFound.
func (s *Store) SetUserPolicy(ctx context.Context, userID uuid.UUID, required bool, method string, auditRecord func(ctx context.Context, tx pgx.Tx) error) error {
	if required && !isEnforceableMfaMethod(method) {
		return ErrMfaMethodUnenforceable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	if err := requireUser(ctx, q, userID); err != nil {
		return err
	}
	global, err := q.GetGlobalMfaPolicy(ctx)
	if err != nil {
		return fmt.Errorf("identity: get global mfa policy: %w", err)
	}
	if mfaPolicyRank(MfaPolicy{Required: required, Method: method}) < mfaPolicyRank(MfaPolicy{Required: global.Required, Method: pgconv.DerefStr(global.Method)}) {
		return ErrMfaPolicyWeakerThanGlobal
	}
	if err := q.UpsertUserMfaPolicy(ctx, UpsertUserMfaPolicyParams{
		SubjectID: pgFromUUID(userID), Required: required, Method: pgconv.StrOrNil(method),
	}); err != nil {
		return fmt.Errorf("identity: set user mfa policy: %w", err)
	}
	if auditRecord != nil {
		if err := auditRecord(ctx, tx); err != nil {
			return fmt.Errorf("identity: audit mutation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("identity: commit tx: %w", err)
	}
	return nil
}

// ClearUserPolicy removes userID's individual override, falling back to the global policy,
// auditing in the same transaction. An unknown user id is ErrUserNotFound.
func (s *Store) ClearUserPolicy(ctx context.Context, userID uuid.UUID, auditRecord func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	if err := requireUser(ctx, q, userID); err != nil {
		return err
	}
	if _, err := q.DeleteUserMfaPolicy(ctx, pgFromUUID(userID)); err != nil {
		return fmt.Errorf("identity: clear user mfa policy: %w", err)
	}
	if auditRecord != nil {
		if err := auditRecord(ctx, tx); err != nil {
			return fmt.Errorf("identity: audit mutation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("identity: commit tx: %w", err)
	}
	return nil
}

// UserPolicyInput is one row of ListEffectivePolicies — a user plus their effective MFA policy,
// for sync.go to reconcile against Keycloak.
type UserPolicyInput struct {
	UserID uuid.UUID
	KcSub  string
	Policy MfaPolicy
}

// ListEffectivePolicies returns every user's effective MFA policy (user override if present,
// else the global row) — drives SyncMfaPolicy.
func (s *Store) ListEffectivePolicies(ctx context.Context) ([]UserPolicyInput, error) {
	q := New(s.pool)
	rows, err := q.ListUserAccountsWithMfaPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: list users with mfa policy: %w", err)
	}
	global, err := q.GetGlobalMfaPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: get global mfa policy: %w", err)
	}

	out := make([]UserPolicyInput, 0, len(rows))
	for _, r := range rows {
		policy := MfaPolicy{Required: global.Required, Method: pgconv.DerefStr(global.Method)}
		if r.Required != nil {
			policy = MfaPolicy{Required: *r.Required, Method: pgconv.DerefStr(r.Method)}
		}
		out = append(out, UserPolicyInput{UserID: uuidFromPg(r.ID), KcSub: r.KcSub, Policy: policy})
	}
	return out, nil
}
