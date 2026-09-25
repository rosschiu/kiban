// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"
)

// GetAssignment and GetOrgUnitType (sqlc-generated) have no production call site yet —
// store.go's own read paths use GetAssignmentOnDate instead. These tests run real SQL against
// the live dev-stack schema, asserting the actual row shape a future call site would depend on.

func TestQueries_GetAssignment(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "QGA1")
	position := mustCreatePosition(t, store, company.ID, company.ID, "QGA-POS")
	member := mustCreateMember(t, store, company.ID, "QGA-MEM")
	created, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID)
	if err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	q := New(orgPool(t))
	row, err := q.GetAssignment(ctx, pgFromUUID(created.ID))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuidFromPg(row.ID) != created.ID {
		t.Errorf("row.ID = %v, want %v", uuidFromPg(row.ID), created.ID)
	}
	if uuidFromPg(row.PositionID) != position.ID || uuidFromPg(row.MemberID) != member.ID {
		t.Errorf("row = %+v, want position=%v member=%v", row, position.ID, member.ID)
	}
}

func TestQueries_GetOrgUnitType(t *testing.T) {
	// org.org_unit_type is seeded by migration 0002 (never truncated by resetOrgFixtures) — the
	// "company" type row is guaranteed to exist.
	q := New(orgPool(t))
	row, err := q.GetOrgUnitType(context.Background(), "company")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row.Key != "company" {
		t.Errorf("row.Key = %q, want company", row.Key)
	}
	if !row.IsCompany {
		t.Errorf("row.IsCompany = false, want true for the company type")
	}
}
