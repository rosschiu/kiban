// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"testing"
)

// This file covers superadmin.go: SeedSuperadmin creates the one-time superadmin's identity row
// inside the caller's transaction, idempotently, and grants nothing (the platform role's one
// record is authz's tuple, written by bootstrap in the same transaction).

func TestSeedSuperadmin_CreatesRowIdempotently(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	pool := identityPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	user, err := SeedSuperadmin(ctx, tx, "kc-sub-superadmin-1", "s1@example.com", "super1")
	if err != nil {
		t.Fatalf("seed superadmin: %v", err)
	}
	if user.KcSub != "kc-sub-superadmin-1" || user.Lifecycle != "active" || user.Email != "s1@example.com" {
		t.Fatalf("unexpected seeded user: %+v", user)
	}
	// Uncommitted: invisible outside the caller's transaction (the row and bootstrap's tuple
	// commit or roll back together).
	if _, err := NewStore(pool).GetUserByKcSub(ctx, "kc-sub-superadmin-1"); err != ErrUserNotFound {
		t.Fatalf("expected the row to be invisible before commit, got err=%v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	again, err := SeedSuperadmin(ctx, pool, "kc-sub-superadmin-1", "s1@example.com", "super1")
	if err != nil {
		t.Fatalf("seed superadmin again: %v", err)
	}
	if again.ID != user.ID {
		t.Fatalf("second seed returned a different row id: %s vs %s", again.ID, user.ID)
	}
}
