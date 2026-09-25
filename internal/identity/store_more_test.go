// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This file covers store.go's MFA policy layering (EffectivePolicy/SetGlobalPolicy/
// SetUserPolicy/ClearUserPolicy), GetUserByID's found and not-found paths, and ListEffectivePolicies' per-user override-vs-global
// branching — all against the real live Postgres dev stack (identityPool, same fixtures helper
// as store_test.go), no mocks.

func TestGetUserByID_FoundAndNotFound(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	if _, err := store.GetUserByID(ctx, uuid.New()); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for an unknown id, got %v", err)
	}

	user, err := store.ResolveOrCreate(ctx, "kc-sub-get-by-id", "g@example.com", "g")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := store.GetUserByID(ctx, user.ID)
	if err != nil || got.ID != user.ID || got.KcSub != "kc-sub-get-by-id" {
		t.Fatalf("GetUserByID(%s) = %+v, %v; want the resolved user", user.ID, got, err)
	}
}

func TestMfaPolicy_EffectivePolicy_FallsBackToGlobal(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-mfa-1", "m1@example.com", "mfa1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// No user override yet: EffectivePolicy falls back to the global row (seeded false/nil by
	// resetIdentityFixtures).
	policy, err := store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy (pre-override): %v", err)
	}
	if policy.Required {
		t.Fatalf("expected default global policy required=false, got %+v", policy)
	}

	if err := store.SetGlobalPolicy(ctx, true, "otp", nil); err != nil {
		t.Fatalf("set global policy: %v", err)
	}
	global, err := store.GetGlobalPolicy(ctx)
	if err != nil {
		t.Fatalf("get global policy: %v", err)
	}
	if !global.Required || global.Method != "otp" {
		t.Fatalf("global policy not updated: %+v", global)
	}

	policy, err = store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy (post-global-set, still no override): %v", err)
	}
	if !policy.Required || policy.Method != "otp" {
		t.Fatalf("expected effective policy to follow the updated global row, got %+v", policy)
	}
}

func TestMfaPolicy_UserOverrideWinsThenClearFallsBack(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-mfa-2", "m2@example.com", "mfa2")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Global stays required=false; the user gets an individual required=true override.
	if err := store.SetUserPolicy(ctx, user.ID, true, "passkey", nil); err != nil {
		t.Fatalf("set user policy: %v", err)
	}

	policy, err := store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy (with override): %v", err)
	}
	if !policy.Required || policy.Method != "passkey" {
		t.Fatalf("expected the user override to win over the global default, got %+v", policy)
	}

	// Re-setting the same user's override upserts rather than duplicating (single-exception
	// model, DB partial unique index).
	if err := store.SetUserPolicy(ctx, user.ID, false, "otp_or_passkey", nil); err != nil {
		t.Fatalf("re-set user policy: %v", err)
	}
	policy, err = store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy (after re-set): %v", err)
	}
	if policy.Required || policy.Method != "otp_or_passkey" {
		t.Fatalf("expected the override to have been replaced, got %+v", policy)
	}

	if err := store.ClearUserPolicy(ctx, user.ID, nil); err != nil {
		t.Fatalf("clear user policy: %v", err)
	}
	policy, err = store.EffectivePolicy(ctx, user.ID)
	if err != nil {
		t.Fatalf("effective policy (after clear): %v", err)
	}
	if policy.Required {
		t.Fatalf("expected fallback to the false global default after clearing the override, got %+v", policy)
	}
}

func TestMfaPolicy_ListEffectivePolicies_MixOfOverrideAndGlobal(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	if err := store.SetGlobalPolicy(ctx, false, "", nil); err != nil {
		t.Fatalf("set global policy: %v", err)
	}

	overridden, err := store.ResolveOrCreate(ctx, "kc-sub-list-1", "l1@example.com", "list1")
	if err != nil {
		t.Fatalf("resolve overridden: %v", err)
	}
	plain, err := store.ResolveOrCreate(ctx, "kc-sub-list-2", "l2@example.com", "list2")
	if err != nil {
		t.Fatalf("resolve plain: %v", err)
	}
	if err := store.SetUserPolicy(ctx, overridden.ID, true, "otp", nil); err != nil {
		t.Fatalf("set user policy: %v", err)
	}

	list, err := store.ListEffectivePolicies(ctx)
	if err != nil {
		t.Fatalf("list effective policies: %v", err)
	}
	byID := map[uuid.UUID]UserPolicyInput{}
	for _, in := range list {
		byID[in.UserID] = in
	}

	got, ok := byID[overridden.ID]
	if !ok || !got.Policy.Required || got.Policy.Method != "otp" || got.KcSub != "kc-sub-list-1" {
		t.Fatalf("expected the overridden user's effective policy to be required=true/otp, got %+v (ok=%v)", got, ok)
	}
	got, ok = byID[plain.ID]
	if !ok || got.Policy.Required {
		t.Fatalf("expected the plain user's effective policy to follow the false global default, got %+v (ok=%v)", got, ok)
	}
}

// TestSyncMfaPolicy_PerUserFailureReportedTruthfully covers sync.go's per-user failure branch
// (SyncOutcome.Success=false, Error populated): SyncMfaPolicy must never claim
// success for a user it couldn't actually reach, and one user's failure must not abort the
// batch (a second, otherwise-identical user in the same run still gets attempted and reported).
func TestSyncMfaPolicy_PerUserFailureReportedTruthfully(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	if _, err := store.ResolveOrCreate(ctx, "kc-sub-sync-fail-1", "sf1@example.com", "sf1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-sync-fail-2", "sf2@example.com", "sf2"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// An AdminClient pointed at an unreachable Keycloak: every SetUserAttribute call fails.
	adminClient := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "realm", "client", "secret")

	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("expected an outcome for both users, got %d", len(outcomes))
	}
	for _, o := range outcomes {
		if o.Success {
			t.Fatalf("expected every outcome to report failure against an unreachable Keycloak, got %+v", o)
		}
		if o.Error == "" {
			t.Fatalf("expected a non-empty error message on a failed outcome, got %+v", o)
		}
	}
}

// TestSyncMfaPolicy_UnenforceablePolicyRefusedPerUser covers sync.go's requiredModeFor-refusal
// branch, a defense-in-depth backstop rather than the primary guard: Store.SetUserPolicy itself
// rejects required=true with an empty/unenforceable method (422 at the HTTP layer), so this
// state cannot be reached via the store's own API — this test writes the row directly with SQL
// (bypassing SetUserPolicy's validation) to prove sync's own refusal still holds for any row
// that predates that check (e.g. a value restored from a backup).
func TestSyncMfaPolicy_UnenforceablePolicyRefusedPerUser(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-sync-nomethod", "nm@example.com", "nm")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Required=true with a NULL method — representable in the DB (method is nullable), but
	// unenforceable by the authenticator, so requiredModeFor must refuse it. Written via direct
	// SQL: Store.SetUserPolicy rejects this combination itself.
	if _, err := admin.Exec(ctx,
		`INSERT INTO identity.mfa_policy (scope, subject_id, required, method) VALUES ('user', $1, true, NULL)`,
		user.ID,
	); err != nil {
		t.Fatalf("seed unenforceable policy via direct SQL: %v", err)
	}

	// Unreachable Keycloak: proves the refusal happens BEFORE any admin write is attempted —
	// the outcome's error must be the mapping refusal, not a connection error.
	adminClient := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "realm", "client", "secret")

	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	var found bool
	for _, o := range outcomes {
		if o.UserID != user.ID {
			continue
		}
		found = true
		if o.Success {
			t.Fatalf("expected the unenforceable policy to be refused, got %+v", o)
		}
		if !strings.Contains(o.Error, "method") {
			t.Fatalf("expected the mapping refusal (not a network error) as the outcome error, got %q", o.Error)
		}
	}
	if !found {
		t.Fatal("no outcome reported for the unenforceable-policy user")
	}
}

// TestSetUserPolicy_UnknownUserErrorRollsBack covers the query-error branch inside the
// tx+audit shape: an FK violation (policy for a user row that doesn't exist) must surface as an
// error from inside the transaction.
func TestSetUserPolicy_UnknownUserErrorRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))

	if err := store.SetUserPolicy(context.Background(), uuid.New(), true, "otp", nil); err == nil {
		t.Fatal("expected an FK violation for a nonexistent user")
	}
}
