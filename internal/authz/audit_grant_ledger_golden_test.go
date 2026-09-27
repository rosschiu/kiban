// SPDX-License-Identifier: Apache-2.0

// A golden test for authz.grant_ledger's SHAPE — column name + Postgres
// type per column, never row values. authz.grant_ledger is store.Grant/Revoke's own ledger (a
// fixed-columns table, not a JSON payload — see internal/authz/store/store.go's insertLedgerSQL),
// so unlike the JSON-payload goldens in the module packages this reads information_schema
// directly rather than internal/testauditgolden.Shape. Same "keys+types, not values" spirit and
// same update-gated convention (UPDATE_AUDIT_GOLDENS=1) as every other audit golden.
package authz

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/testauditgolden"
)

func TestAuditGolden_GrantLedgerShape(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()

	// Drive a real Grant + Revoke through the production API (store.Grant/store.Revoke) inside
	// a throwaway tx that's rolled back, so this test never leaves a stray ledger row behind —
	// the point is proving the TABLE shape, not this call's own data.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tp := store.Tuple{ObjectType: "position", ObjectID: "audgl-1", Relation: "holder", SubjectType: "member", SubjectID: "audgl-m1"}
	if err := store.Grant(ctx, tx, "test-actor", "corr-1", tp); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := store.Revoke(ctx, tx, "test-actor", "", tp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'authz' AND table_name = 'grant_ledger'
		ORDER BY column_name`)
	if err != nil {
		t.Fatalf("query information_schema.columns: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var col, dtype, nullable string
		if err := rows.Scan(&col, &dtype, &nullable); err != nil {
			t.Fatalf("scan: %v", err)
		}
		lines = append(lines, col+":"+dtype+":"+strings.ToLower(nullable))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"

	path := filepath.Join("testdata", "audit_golden_authz_grant_ledger_shape.txt")
	testauditgolden.AssertGolden(t, path, got)
}
