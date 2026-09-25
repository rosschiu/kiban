// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// revokeCleanup removes any tuple/grant_ledger rows this file's tests left behind.
func revokeCleanup(t *testing.T, objectType, objectID string) {
	t.Helper()
	admin := adminPool(t)
	ctx := context.Background()
	if _, err := admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type=$1 AND object_id=$2`, objectType, objectID); err != nil {
		t.Fatalf("cleanup tuple: %v", err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type=$1 AND object_id=$2`, objectType, objectID); err != nil {
		t.Fatalf("cleanup grant_ledger: %v", err)
	}
}

// TestRevokePositionOrMemberTuple_PositionHolderShape proves the SECURITY DEFINER
// revocation path for the position:*#holder shape: a granted tuple is deleted and a 'revoke'
// grant_ledger row is written, both via the function migrations/authz/0006 creates — never a raw
// DELETE from application code.
func TestRevokePositionOrMemberTuple_PositionHolderShape(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	objectID := "RVA-POS-1"
	t.Cleanup(func() { revokeCleanup(t, "position", objectID) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "", store.Tuple{
		ObjectType: "position", ObjectID: objectID, Relation: "holder",
		SubjectType: "member", SubjectID: "RVA-MEM-1", SubjectRelation: "mapped_user",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit grant: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revoke tx: %v", err)
	}
	if err := store.RevokePositionOrMemberTuple(ctx, tx2, "test-actor", "", store.Tuple{
		ObjectType: "position", ObjectID: objectID, Relation: "holder",
		SubjectType: "member", SubjectID: "RVA-MEM-1", SubjectRelation: "mapped_user",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit revoke: %v", err)
	}

	var tupleCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='position' AND object_id=$1`, objectID).Scan(&tupleCount); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if tupleCount != 0 {
		t.Errorf("tuple count = %d, want 0 (revoked)", tupleCount)
	}

	var ledgerOp string
	if err := pool.QueryRow(ctx, `
		SELECT op FROM authz.grant_ledger WHERE object_type='position' AND object_id=$1 ORDER BY id DESC LIMIT 1`,
		objectID,
	).Scan(&ledgerOp); err != nil {
		t.Fatalf("query ledger: %v", err)
	}
	if ledgerOp != "revoke" {
		t.Errorf("ledger op = %q, want revoke", ledgerOp)
	}
}

// TestRevokePositionOrMemberTuple_MemberMappedUserShape proves the second allowed shape
// (member:*#mapped_user objects, user subjects).
func TestRevokePositionOrMemberTuple_MemberMappedUserShape(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	objectID := "RVA-MEM-2"
	t.Cleanup(func() { revokeCleanup(t, "member", objectID) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "", store.Tuple{
		ObjectType: "member", ObjectID: objectID, Relation: "mapped_user",
		SubjectType: "user", SubjectID: "kc-sub-407",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit grant: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revoke tx: %v", err)
	}
	if err := store.RevokePositionOrMemberTuple(ctx, tx2, "test-actor", "", store.Tuple{
		ObjectType: "member", ObjectID: objectID, Relation: "mapped_user",
		SubjectType: "user", SubjectID: "kc-sub-407",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit revoke: %v", err)
	}

	var tupleCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='member' AND object_id=$1`, objectID).Scan(&tupleCount); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if tupleCount != 0 {
		t.Errorf("tuple count = %d, want 0 (revoked)", tupleCount)
	}
}

// TestRevokePositionOrMemberTuple_GroupMemberShape proves the extension
// (migrations/authz/0007): the third allowed shape, group:*#member objects with
// member:*#mapped_user subjects — org's group single-writer invariant revokes through this SAME
// SECURITY DEFINER function, never a raw DELETE.
func TestRevokePositionOrMemberTuple_GroupMemberShape(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	objectID := "RVB-GRP-1"
	t.Cleanup(func() { revokeCleanup(t, "group", objectID) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "", store.Tuple{
		ObjectType: "group", ObjectID: objectID, Relation: "member",
		SubjectType: "member", SubjectID: "RVB-MEM-1", SubjectRelation: "mapped_user",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit grant: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revoke tx: %v", err)
	}
	if err := store.RevokePositionOrMemberTuple(ctx, tx2, "test-actor", "", store.Tuple{
		ObjectType: "group", ObjectID: objectID, Relation: "member",
		SubjectType: "member", SubjectID: "RVB-MEM-1", SubjectRelation: "mapped_user",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit revoke: %v", err)
	}

	var tupleCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='group' AND object_id=$1`, objectID).Scan(&tupleCount); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if tupleCount != 0 {
		t.Errorf("tuple count = %d, want 0 (revoked)", tupleCount)
	}

	var ledgerOp string
	if err := pool.QueryRow(ctx, `
		SELECT op FROM authz.grant_ledger WHERE object_type='group' AND object_id=$1 ORDER BY id DESC LIMIT 1`,
		objectID,
	).Scan(&ledgerOp); err != nil {
		t.Fatalf("query ledger: %v", err)
	}
	if ledgerOp != "revoke" {
		t.Errorf("ledger op = %q, want revoke", ledgerOp)
	}
}

// TestRevokePositionOrMemberTuple_RejectsOtherShapes proves the function's hard-coded allow-list:
// ANY tuple shape outside the allow-list (e.g. a company_module tuple) is refused — this is
// never a general-purpose revoke, and no application code has any other way to DELETE a row from
// authz.tuple (kiban_org has no DELETE grant at all).
func TestRevokePositionOrMemberTuple_RejectsOtherShapes(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	objectID := "RVA-REJECT-1/helpdesk"
	t.Cleanup(func() { revokeCleanup(t, "company_module", objectID) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "", store.Tuple{
		ObjectType: "company_module", ObjectID: objectID, Relation: "editor",
		SubjectType: "user", SubjectID: "kc-sub-reject",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit grant: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revoke tx: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	err = store.RevokePositionOrMemberTuple(ctx, tx2, "test-actor", "", store.Tuple{
		ObjectType: "company_module", ObjectID: objectID, Relation: "editor",
		SubjectType: "user", SubjectID: "kc-sub-reject",
	})
	if err == nil {
		t.Fatal("expected an error rejecting the disallowed tuple shape, got nil")
	}
	if !strings.Contains(err.Error(), "revoke position/member tuple") {
		t.Errorf("error = %v, want a wrapped revoke-position/member error", err)
	}

	var tupleCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, objectID).Scan(&tupleCount); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if tupleCount != 1 {
		t.Errorf("tuple count = %d, want 1 (the disallowed-shape tuple must survive)", tupleCount)
	}
}
