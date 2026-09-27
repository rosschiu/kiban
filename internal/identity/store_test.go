// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"testing"
)

// TestResolveOrCreate_Idempotent proves resolve-or-create is idempotent: calling it twice with
// the same kc_sub returns the same row id, and never creates a second user_account row.
func TestResolveOrCreate_Idempotent(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	first, err := store.ResolveOrCreate(ctx, "kc-sub-1", "a@example.com", "alice")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := store.ResolveOrCreate(ctx, "kc-sub-1", "a@example.com", "alice")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("resolve-or-create not idempotent: first id %s, second id %s", first.ID, second.ID)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM identity.user_account WHERE kc_sub = $1`, "kc-sub-1").Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 user_account row for kc-sub-1, got %d", count)
	}
}

// TestResolveOrCreate_RefreshesClaims proves the upsert path refreshes email/preferred_username
// from the latest bearer claims while keeping the same identity row.
func TestResolveOrCreate_RefreshesClaims(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	first, err := store.ResolveOrCreate(ctx, "kc-sub-2", "old@example.com", "old-name")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := store.ResolveOrCreate(ctx, "kc-sub-2", "new@example.com", "new-name")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("id changed across resolves: %s -> %s", first.ID, second.ID)
	}
	if second.Email != "new@example.com" || second.PreferredUsername != "new-name" {
		t.Fatalf("claims not refreshed: got email=%q username=%q", second.Email, second.PreferredUsername)
	}
}

// TestResolveOrCreate_DoesNotTouchLoginObservation is the table-separation proof: the
// identity upsert must never create/modify a user_login_observation row.
func TestResolveOrCreate_DoesNotTouchLoginObservation(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	user, err := store.ResolveOrCreate(ctx, "kc-sub-3", "c@example.com", "carol")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM identity.user_login_observation WHERE user_id = $1`, user.ID).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("resolve-or-create must never write user_login_observation, found %d row(s)", count)
	}
}
