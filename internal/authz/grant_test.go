// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/livestack"
)

// --- dbtest plumbing: internal/livestack ---

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

func authzPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_authz", testEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
}

// adminPool connects as the migration-owner role (kiban) — used only for DDL the runtime role
// (kiban_authz) has no rights to perform (e.g. TestGrantBusinessWriteAtomic's local fixture
// table, standing in for another service's own schema).
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// --- grant/revoke ---

func TestGrantBasic(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tp := store.Tuple{ObjectType: "company", ObjectID: "grant-c1", Relation: "admin", SubjectType: "user", SubjectID: "grant-u1"}
	if err := store.Grant(ctx, tx, "test-actor", "corr-1", tp); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'grant-%'`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'grant-%'`)
	})

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company' AND object_id='grant-c1' AND relation='admin' AND subject_id='grant-u1'`).Scan(&count); err != nil {
		t.Fatalf("verify tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("tuple count = %d, want 1", count)
	}

	var ledgerCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_ledger WHERE object_id='grant-c1' AND op='grant' AND actor='test-actor' AND correlation_id='corr-1'`).Scan(&ledgerCount); err != nil {
		t.Fatalf("verify ledger: %v", err)
	}
	if ledgerCount != 1 {
		t.Fatalf("ledger count = %d, want 1", ledgerCount)
	}
}

func TestGrantRevoke(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'grant-rv-%'`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'grant-rv-%'`)
	})

	tp := store.Tuple{ObjectType: "company", ObjectID: "grant-rv-c1", Relation: "admin", SubjectType: "user", SubjectID: "grant-rv-u1"}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "", tp); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("Grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	if err := store.Revoke(ctx, tx2, "test-actor", "", tp); err != nil {
		tx2.Rollback(ctx) //nolint:errcheck
		t.Fatalf("Revoke: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit 2: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_id='grant-rv-c1'`).Scan(&count); err != nil {
		t.Fatalf("verify tuple gone: %v", err)
	}
	if count != 0 {
		t.Fatalf("tuple count after revoke = %d, want 0", count)
	}

	var revokeLedgerCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_ledger WHERE object_id='grant-rv-c1' AND op='revoke'`).Scan(&revokeLedgerCount); err != nil {
		t.Fatalf("verify revoke ledger: %v", err)
	}
	if revokeLedgerCount != 1 {
		t.Fatalf("revoke ledger count = %d, want 1", revokeLedgerCount)
	}
}

// setupBusinessFixture creates a minimal local table simulating "another service's business
// write" (e.g. org creating a position); the point is that authz.store.Grant participates
// correctly in an AMBIENT caller transaction and rolls back with it, without this test
// importing internal/org. The table is created as the migration-owner role (kiban_authz has
// no DDL rights) and the runtime role is granted DML on it, so the transaction under test
// still runs entirely as kiban_authz — the same role the real service runs as.
func setupBusinessFixture(t *testing.T, authz *pgxpool.Pool) {
	t.Helper()
	admin := adminPool(t)
	ctx := context.Background()
	_, err := admin.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS authz.grant_business_fixture (
			id text PRIMARY KEY,
			must_be_unique text NOT NULL UNIQUE
		);
		GRANT SELECT, INSERT, UPDATE, DELETE ON authz.grant_business_fixture TO kiban_authz;`)
	if err != nil {
		t.Fatalf("create business fixture table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP TABLE IF EXISTS authz.grant_business_fixture`)
	})
}

// TestGrantBusinessWriteAtomic demonstrates that a business write (here, the
// local fixture table standing in for "create an org position") and its authz owner tuple
// commit together in ONE transaction; an induced failure (a UNIQUE violation on the second
// business row) rolls back BOTH the business write and the tuple that was granted earlier in
// the SAME transaction. This proves Grant is safely reusable inside an ambient pgx.Tx.
func TestGrantBusinessWriteAtomic(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	setupBusinessFixture(t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'grant-biz-%'`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'grant-biz-%'`)
	})

	t.Run("success case: business write + tuple commit together", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		if _, err := tx.Exec(ctx, `INSERT INTO authz.grant_business_fixture (id, must_be_unique) VALUES ($1, $2)`, "grant-biz-pos-1", "u1"); err != nil {
			t.Fatalf("insert business row: %v", err)
		}
		tp := store.Tuple{ObjectType: "position", ObjectID: "grant-biz-pos-1", Relation: "owner", SubjectType: "user", SubjectID: "grant-biz-member-1"}
		if err := store.Grant(ctx, tx, "test-actor", "", tp); err != nil {
			t.Fatalf("Grant: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		var bizCount, tupleCount int
		pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_business_fixture WHERE id='grant-biz-pos-1'`).Scan(&bizCount)
		pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_id='grant-biz-pos-1'`).Scan(&tupleCount)
		if bizCount != 1 || tupleCount != 1 {
			t.Fatalf("after commit: bizCount=%d tupleCount=%d, want 1,1", bizCount, tupleCount)
		}
	})

	t.Run("induced failure rolls back both the business row and the tuple", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO authz.grant_business_fixture (id, must_be_unique) VALUES ($1, $2)`, "grant-biz-pos-2", "u2"); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("insert business row: %v", err)
		}
		tp := store.Tuple{ObjectType: "position", ObjectID: "grant-biz-pos-2", Relation: "owner", SubjectType: "user", SubjectID: "grant-biz-member-2"}
		if err := store.Grant(ctx, tx, "test-actor", "", tp); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("Grant: %v", err)
		}

		// Induce a failure: a second business row with the SAME must_be_unique value violates
		// the UNIQUE constraint — the whole transaction, including the tuple grant above and
		// the first business row, must roll back.
		_, err = tx.Exec(ctx, `INSERT INTO authz.grant_business_fixture (id, must_be_unique) VALUES ($1, $2)`, "grant-biz-pos-2-dup", "u2")
		if err == nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("expected UNIQUE violation, got no error")
		}
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			t.Fatalf("rollback: %v", rbErr)
		}

		var bizCount, tupleCount, ledgerCount int
		pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_business_fixture WHERE id='grant-biz-pos-2'`).Scan(&bizCount)
		pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_id='grant-biz-pos-2'`).Scan(&tupleCount)
		pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_ledger WHERE object_id='grant-biz-pos-2'`).Scan(&ledgerCount)
		if bizCount != 0 || tupleCount != 0 || ledgerCount != 0 {
			t.Fatalf("after rollback: bizCount=%d tupleCount=%d ledgerCount=%d, want 0,0,0 — atomicity broken", bizCount, tupleCount, ledgerCount)
		}
	})
}
