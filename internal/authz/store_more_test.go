// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// This file backfills store.go's remaining branches beyond grant_test.go's grant/revoke
// suite: writeTuples' own "at least one tuple" guard (only ever reached today via handleGrants'
// own separate empty-tuples check, in http_test.go — this proves store.Grant/Revoke enforce it
// themselves too, independent of any HTTP caller), and the SQL-exec error paths for both the
// tuple insert and the tuple delete, using an already-committed (closed) transaction so pgx
// itself rejects further Exec calls — a real Postgres/pgx error, not a mock.

func TestStoreGrantRevokeRequireAtLeastOneTuple(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()

	t.Run("Grant with zero tuples", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := store.Grant(ctx, tx, "test-actor", ""); err == nil {
			t.Fatal("Grant with zero tuples: want error, got nil")
		}
	})

	t.Run("Revoke with zero tuples", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := store.Revoke(ctx, tx, "test-actor", ""); err == nil {
			t.Fatal("Revoke with zero tuples: want error, got nil")
		}
	})
}

// TestStoreGrantRevokeSQLExecErrors uses an already-committed transaction — every further Exec
// on it fails at the pgx level ("tx is closed") — to exercise writeTuples' insert-tuple and
// delete-tuple SQL-error wrapping branches with a genuine Postgres/pgx failure.
func TestStoreGrantRevokeSQLExecErrors(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	tp := store.Tuple{ObjectType: "company", ObjectID: "closed-tx-test", Relation: "admin", SubjectType: "user", SubjectID: "u1"}

	t.Run("Grant on an already-committed tx", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit (to close the tx early): %v", err)
		}
		if err := store.Grant(ctx, tx, "test-actor", "", tp); err == nil {
			t.Fatal("Grant on a closed tx: want a wrapped SQL error, got nil")
		}
	})

	t.Run("Revoke on an already-committed tx", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit (to close the tx early): %v", err)
		}
		if err := store.Revoke(ctx, tx, "test-actor", "", tp); err == nil {
			t.Fatal("Revoke on a closed tx: want a wrapped SQL error, got nil")
		}
	})
}
