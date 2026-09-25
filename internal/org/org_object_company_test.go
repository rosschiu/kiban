// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// orgObjectCompanyTupleCount counts `<objType>:<id>#company @ company:<companyId>` rows — the
// anchor the authz decision layer binds a position/group object check to the request's company
// through.
func orgObjectCompanyTupleCount(t *testing.T, objType string, id, companyID uuid.UUID) int {
	t.Helper()
	var c int
	if err := adminPool(t).QueryRow(context.Background(), `
		SELECT count(*) FROM authz.tuple
		WHERE object_type=$1 AND object_id=$2 AND relation='company'
		  AND subject_type='company' AND subject_id=$3 AND subject_relation=''`,
		objType, id.String(), companyID.String()).Scan(&c); err != nil {
		t.Fatalf("query %s company tuple: %v", objType, err)
	}
	return c
}

// TestOrgObjectCompanyTuple_PositionLifecycle proves CreatePosition grants the position's
// company anchor in the same transaction as the row, and DeletePosition revokes it (via the
// SECURITY DEFINER seam migrations/authz/0009 widened) so no anchor outlives its position.
func TestOrgObjectCompanyTuple_PositionLifecycle(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "OOC1")
	position := mustCreatePosition(t, store, company.ID, company.ID, "OOC1-POS")
	if got := orgObjectCompanyTupleCount(t, "position", position.ID, company.ID); got != 1 {
		t.Fatalf("after create: position company tuple count = %d, want 1", got)
	}

	if err := store.DeletePosition(ctx, "test-actor", position.ID); err != nil {
		t.Fatalf("DeletePosition: %v", err)
	}
	if got := orgObjectCompanyTupleCount(t, "position", position.ID, company.ID); got != 0 {
		t.Fatalf("after delete: position company tuple count = %d, want 0 (revoked in the delete tx)", got)
	}
	var revoked int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.grant_ledger
		WHERE object_type='position' AND object_id=$1 AND relation='company' AND op='revoke'`,
		position.ID.String()).Scan(&revoked); err != nil {
		t.Fatalf("query ledger: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoke ledger rows = %d, want 1", revoked)
	}
}

// TestOrgObjectCompanyTuple_GroupCreate proves CreateGroup grants the group's company anchor
// in the same transaction as the row (org has no group delete, so create is the only path).
func TestOrgObjectCompanyTuple_GroupCreate(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)

	company := mustCreateCompany(t, store, "OOC2")
	group := mustCreateGroup(t, store, company.ID, "OOC2-GRP")
	if got := orgObjectCompanyTupleCount(t, "group", group.ID, company.ID); got != 1 {
		t.Fatalf("after create: group company tuple count = %d, want 1", got)
	}
}
