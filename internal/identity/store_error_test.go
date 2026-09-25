// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This file covers store.go/superadmin.go/sync.go's error-wrap branches — the
// `if err != nil { return ..., fmt.Errorf(...) }` lines after nearly every query, which the
// happy-path tests elsewhere in this package never reach. An already-canceled context is the
// standard, dependency-free way to force a real pgx query error deterministically (pgx checks
// ctx.Err() and fails fast) — this tests each method's real error-propagation behavior against
// the real live Postgres driver, not a mock of the DB.

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestCheckMigrationsApplied_QueryErrorPropagates(t *testing.T) {
	if err := CheckMigrationsApplied(canceledCtx(), adminPool(t)); err == nil {
		t.Fatal("expected an error when the query context is already canceled")
	}
}

func TestStoreQueryMethods_PropagateContextError(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := canceledCtx()
	userID := uuid.New()

	cases := []struct {
		name string
		call func() error
	}{
		{"ResolveOrCreate", func() error { _, err := store.ResolveOrCreate(ctx, "x", "x@example.com", "x"); return err }},
		{"GetUserByKcSub", func() error { _, err := store.GetUserByKcSub(ctx, "x"); return err }},
		{"GetUserByID", func() error { _, err := store.GetUserByID(ctx, userID); return err }},
		{"EffectivePolicy", func() error { _, err := store.EffectivePolicy(ctx, userID); return err }},
		{"GetGlobalPolicy", func() error { _, err := store.GetGlobalPolicy(ctx); return err }},
		{"SetGlobalPolicy", func() error { return store.SetGlobalPolicy(ctx, true, "otp", nil) }},
		{"SetUserPolicy", func() error { return store.SetUserPolicy(ctx, userID, true, "otp", nil) }},
		{"ClearUserPolicy", func() error { return store.ClearUserPolicy(ctx, userID, nil) }},
		{"ListEffectivePolicies", func() error { _, err := store.ListEffectivePolicies(ctx); return err }},
		{"SeedSuperadmin", func() error { _, err := SeedSuperadmin(ctx, store.pool, "x", "x@example.com", "x"); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatalf("%s: expected an error with an already-canceled context", tc.name)
			}
		})
	}
}

// TestSetGlobalPolicy_RequiredWithoutMethodRejected and TestSetUserPolicy_RequiredWithoutMethodRejected
// prove required=true paired with an empty or unrecognized method is rejected BEFORE
// any transaction begins — no audit callback invocation, no DB write attempted at all — and the
// existing policy (if any) is left untouched.
func TestSetGlobalPolicy_RequiredWithoutMethodRejected(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	for _, method := range []string{"", "bogus", "OTP"} {
		callbackInvoked := false
		err := store.SetGlobalPolicy(ctx, true, method, func(ctx context.Context, tx pgx.Tx) error {
			callbackInvoked = true
			return nil
		})
		if !errors.Is(err, ErrMfaMethodUnenforceable) {
			t.Fatalf("method=%q: err = %v, want ErrMfaMethodUnenforceable", method, err)
		}
		if callbackInvoked {
			t.Fatalf("method=%q: audit callback must not run when the write is rejected pre-transaction", method)
		}
	}

	got, err := store.GetGlobalPolicy(ctx)
	if err != nil {
		t.Fatalf("get global policy: %v", err)
	}
	if got.Required {
		t.Fatalf("expected the global policy to remain untouched, got %+v", got)
	}
}

func TestSetUserPolicy_RequiredWithoutMethodRejected(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-setuser-nomethod", "sn@example.com", "sn")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	callbackInvoked := false
	err = store.SetUserPolicy(ctx, user.ID, true, "", func(ctx context.Context, tx pgx.Tx) error {
		callbackInvoked = true
		return nil
	})
	if !errors.Is(err, ErrMfaMethodUnenforceable) {
		t.Fatalf("err = %v, want ErrMfaMethodUnenforceable", err)
	}
	if callbackInvoked {
		t.Fatal("audit callback must not run when the write is rejected pre-transaction")
	}

	policy, err := store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy: %v", err)
	}
	if policy.Required {
		t.Fatalf("expected no user override to have been persisted, got %+v", policy)
	}
}

// TestSetGlobalPolicy_AuditCallbackErrorRollsBack proves the fail-closed rule for the
// identity.mfa_policy.set_global handler: SetGlobalPolicy takes the tx+auditRecord-callback
// shape (store.go), so a failing audit callback must roll back the policy write.
func TestSetGlobalPolicy_AuditCallbackErrorRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	// Seed a known starting value so a rolled-back write is observable.
	if err := store.SetGlobalPolicy(ctx, false, "", nil); err != nil {
		t.Fatalf("seed global policy: %v", err)
	}

	wantErr := errors.New("boom")
	err := store.SetGlobalPolicy(ctx, true, "otp", func(ctx context.Context, tx pgx.Tx) error {
		return wantErr
	})
	if err == nil {
		t.Fatal("expected the audit callback's error to propagate")
	}

	got, err := store.GetGlobalPolicy(ctx)
	if err != nil {
		t.Fatalf("get global policy: %v", err)
	}
	if got.Required {
		t.Fatalf("expected the global policy write to have rolled back when the audit callback failed, got %+v", got)
	}
}

// TestSetUserPolicy_AuditCallbackErrorRollsBack mirrors the global-policy proof above for the
// per-user override (identity.mfa_policy.set_user).
func TestSetUserPolicy_AuditCallbackErrorRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-setuser-audit-fail", "su@example.com", "su")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	wantErr := errors.New("boom")
	err = store.SetUserPolicy(ctx, user.ID, true, "otp", func(ctx context.Context, tx pgx.Tx) error {
		return wantErr
	})
	if err == nil {
		t.Fatal("expected the audit callback's error to propagate")
	}

	policy, err := store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy: %v", err)
	}
	if policy.Required {
		t.Fatalf("expected no user override to have been persisted when the audit callback failed, got %+v", policy)
	}
}

// TestClearUserPolicy_AuditCallbackErrorRollsBack mirrors the same proof for
// identity.mfa_policy.clear_user: the override row must survive when the audit callback fails.
func TestClearUserPolicy_AuditCallbackErrorRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-clearuser-audit-fail", "cu@example.com", "cu")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := store.SetUserPolicy(ctx, user.ID, true, "otp", nil); err != nil {
		t.Fatalf("set user policy: %v", err)
	}

	wantErr := errors.New("boom")
	err = store.ClearUserPolicy(ctx, user.ID, func(ctx context.Context, tx pgx.Tx) error {
		return wantErr
	})
	if err == nil {
		t.Fatal("expected the audit callback's error to propagate")
	}

	policy, err := store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy: %v", err)
	}
	if !policy.Required || policy.Method != "otp" {
		t.Fatalf("expected the user override to survive when the audit callback failed, got %+v", policy)
	}
}

func TestNewTokenVerifier_FetchError(t *testing.T) {
	if _, err := NewTokenVerifier(context.Background(), "http://127.0.0.1:1/jwks", "issuer", "aud"); err == nil {
		t.Fatal("expected an error when the JWKS endpoint is unreachable")
	}
}

func TestSyncMfaPolicy_ListEffectivePoliciesErrorPropagates(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	adminClient := NewAdminClient(nil, "http://127.0.0.1:1", "realm", "client", "secret")

	if _, err := store.SyncMfaPolicy(canceledCtx(), adminClient); err == nil {
		t.Fatal("expected an error when the underlying ListEffectivePolicies query fails")
	}
}

// TestPolicyMutations_BeginTxErrorPropagates covers the begin-tx error branch of every policy
// mutation's tx+audit-callback shape: a canceled context makes
// pool.Begin fail before any state or audit write happens.
func TestPolicyMutations_BeginTxErrorPropagates(t *testing.T) {
	store := NewStore(identityPool(t))
	ctx := canceledCtx()
	userID := uuid.New()

	if err := store.SetGlobalPolicy(ctx, true, "otp", nil); err == nil {
		t.Error("SetGlobalPolicy: expected a begin-tx error with a canceled context")
	}
	if err := store.SetUserPolicy(ctx, userID, true, "otp", nil); err == nil {
		t.Error("SetUserPolicy: expected a begin-tx error with a canceled context")
	}
	if err := store.ClearUserPolicy(ctx, userID, nil); err == nil {
		t.Error("ClearUserPolicy: expected a begin-tx error with a canceled context")
	}
}
