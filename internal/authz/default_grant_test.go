// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// execCleanup removes any default_grant/tuple/grant_ledger rows this file's tests left behind,
// keyed on a per-test companyID so runs never collide.
func execCleanup(t *testing.T, companyID, moduleKey string) {
	t.Helper()
	admin := adminPool(t)
	ctx := context.Background()
	objectID := companyID + "/" + moduleKey
	if _, err := admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE company_id=$1 AND module_key=$2`, companyID, moduleKey); err != nil {
		t.Fatalf("cleanup default_grant: %v", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, objectID); err != nil {
		t.Fatalf("cleanup tuple: %v", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id=$1`, objectID); err != nil {
		t.Fatalf("cleanup grant_ledger: %v", err)
	}
}

// TestEnsureDefaultGrant_FirstCallWrites proves the core behaviour: the first call for a
// never-before-seen (companyID, moduleKey) pair grants
// `company_module:<companyID>/<moduleKey>#system @ system:platform` through store.Grant (an
// audited grant_ledger row, not a raw INSERT) and returns applied=true.
func TestEnsureDefaultGrant_FirstCallWrites(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	companyID, moduleKey := "DG-COMPANY-1", "notification"
	t.Cleanup(func() { execCleanup(t, companyID, moduleKey) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	applied, err := store.EnsureDefaultGrant(ctx, tx, "test-actor", "", companyID, moduleKey)
	if err != nil {
		t.Fatalf("EnsureDefaultGrant: %v", err)
	}
	if !applied {
		t.Fatal("first call: want applied=true")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='system'
		  AND subject_type='system' AND subject_id=$2`,
		companyID+"/"+moduleKey, store.SystemPlatformID,
	).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("tuple count = %d, want 1", count)
	}

	var ledgerCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.grant_ledger
		WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND op='grant'`,
		companyID+"/"+moduleKey,
	).Scan(&ledgerCount); err != nil {
		t.Fatalf("query grant_ledger: %v", err)
	}
	if ledgerCount != 1 {
		t.Fatalf("grant_ledger count = %d, want 1 (audited)", ledgerCount)
	}
}

// TestEnsureDefaultGrant_SecondCallIsNoop proves default-ONCE: calling again for the SAME pair
// (even though the tuple is still present) never writes a second tuple or ledger row.
func TestEnsureDefaultGrant_SecondCallIsNoop(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	companyID, moduleKey := "DG-COMPANY-2", "notification"
	t.Cleanup(func() { execCleanup(t, companyID, moduleKey) })

	grantOnce := func() bool {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		applied, err := store.EnsureDefaultGrant(ctx, tx, "test-actor", "", companyID, moduleKey)
		if err != nil {
			t.Fatalf("EnsureDefaultGrant: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return applied
	}

	if !grantOnce() {
		t.Fatal("first call: want applied=true")
	}
	if grantOnce() {
		t.Fatal("second call: want applied=false (default-ONCE)")
	}
	if grantOnce() {
		t.Fatal("third call: want applied=false (default-ONCE)")
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1 AND relation='system'`, companyID+"/"+moduleKey).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("tuple count = %d, want exactly 1 (no duplicate)", count)
	}
	if got := anchorCount(t, pool, companyID, moduleKey); got != 1 {
		t.Fatalf("company anchor count after three calls = %d, want exactly 1 (ensure-always, never duplicated)", got)
	}
}

// TestEnsureDefaultGrant_NeverResurrectsARemovedGrant proves the product requirement: once a
// human excludes a company+module by deleting the tuple, re-running the
// default-grant writer for the SAME pair must NOT bring it back — the bookkeeping claim in
// authz.default_grant, not the tuple's current presence, is what gates re-granting.
func TestEnsureDefaultGrant_NeverResurrectsARemovedGrant(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	companyID, moduleKey := "DG-COMPANY-3", "notification"
	t.Cleanup(func() { execCleanup(t, companyID, moduleKey) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := store.EnsureDefaultGrant(ctx, tx, "test-actor", "", companyID, moduleKey); err != nil {
		t.Fatalf("EnsureDefaultGrant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Simulate a revoke: delete the tuple directly.
	objectID := companyID + "/" + moduleKey
	if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, objectID); err != nil {
		t.Fatalf("delete tuple: %v", err)
	}

	// Re-run the writer for the SAME pair (standing in for a bootstrap converge / registry
	// restart rerun) — must be a no-op.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	applied, err := store.EnsureDefaultGrant(ctx, tx2, "test-actor", "", companyID, moduleKey)
	if err != nil {
		t.Fatalf("EnsureDefaultGrant (rerun): %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if applied {
		t.Fatal("rerun after exclusion: want applied=false (must never resurrect)")
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1 AND relation='system'`, objectID).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 0 {
		t.Fatalf("tuple count = %d, want 0 (stays excluded)", count)
	}
	// The anchor is structural, not a grant: the rerun restores it even though the default
	// grant stays excluded.
	if got := anchorCount(t, pool, companyID, moduleKey); got != 1 {
		t.Fatalf("company anchor count after rerun = %d, want 1 (ensure-always)", got)
	}
}

// TestEnsureDefaultGrant_ConcurrentCallersExactlyOneWins proves the concurrency claim: two
// callers racing to default-grant the SAME pair must result in exactly one applied=true and
// exactly one authz.tuple row — never a duplicate, never a lost update.
func TestEnsureDefaultGrant_ConcurrentCallersExactlyOneWins(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	companyID, moduleKey := "DG-COMPANY-4", "notification"
	t.Cleanup(func() { execCleanup(t, companyID, moduleKey) })

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	appliedCount := 0
	errs := make([]error, n)

	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tx, err := pool.Begin(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			applied, err := store.EnsureDefaultGrant(ctx, tx, "test-actor", "", companyID, moduleKey)
			if err != nil {
				errs[i] = err
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errs[i] = err
				return
			}
			if applied {
				mu.Lock()
				appliedCount++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureDefaultGrant: %v", err)
		}
	}
	if appliedCount != 1 {
		t.Fatalf("appliedCount = %d, want exactly 1", appliedCount)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1 AND relation='system'`, companyID+"/"+moduleKey).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("tuple count = %d, want exactly 1", count)
	}
	if got := anchorCount(t, pool, companyID, moduleKey); got != 1 {
		t.Fatalf("company anchor count under concurrency = %d, want exactly 1", got)
	}
}

// anchorCount counts `company_module:<c>/<m>#company @ company:<c>` rows.
func anchorCount(t *testing.T, pool *pgxpool.Pool, companyID, moduleKey string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='company'
		  AND subject_type='company' AND subject_id=$2 AND subject_relation=''`,
		companyID+"/"+moduleKey, companyID).Scan(&n); err != nil {
		t.Fatalf("query anchor: %v", err)
	}
	return n
}

// TestEnsureDefaultGrant_WritesCompanyAnchorOnce proves the company anchor is written once: the first call
// writes `company_module:<c>/<m>#company @ company:<c>` with exactly one audited ledger row,
// and a rerun writes neither a second tuple nor a second ledger row.
func TestEnsureDefaultGrant_WritesCompanyAnchorOnce(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	companyID, moduleKey := "DG-COMPANY-5", "notification"
	t.Cleanup(func() { execCleanup(t, companyID, moduleKey) })

	for i := 0; i < 2; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := store.EnsureDefaultGrant(ctx, tx, "test-actor", "", companyID, moduleKey); err != nil {
			t.Fatalf("EnsureDefaultGrant #%d: %v", i+1, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	if got := anchorCount(t, pool, companyID, moduleKey); got != 1 {
		t.Fatalf("anchor count = %d, want 1", got)
	}
	var ledger int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.grant_ledger
		WHERE object_type='company_module' AND object_id=$1 AND relation='company' AND op='grant'`,
		companyID+"/"+moduleKey).Scan(&ledger); err != nil {
		t.Fatalf("query ledger: %v", err)
	}
	if ledger != 1 {
		t.Fatalf("anchor ledger rows = %d, want 1 (audited once, silent on rerun)", ledger)
	}
}
