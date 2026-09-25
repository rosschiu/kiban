// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
)

// This file proves the store-level cross-company checks (application-level UX, 422
// VALIDATION_FAILED) ahead of migration 0004_cross_company_constraints.sql's trigger backstop.
//
// TestConstraints_TriggerRejectsCrossCompany* below additionally proves the DB-layer trigger
// itself, but SKIPS (rather than failing) if migration 0004 hasn't been applied to this database.

// TestCreatePosition_RejectsOrgUnitOutsideCompany proves CreatePosition's store-level check: an
// org_unit belonging to a DIFFERENT company's tree is rejected with a 422-shaped ValidationError,
// never a raw FK/trigger 500.
func TestCreatePosition_RejectsOrgUnitOutsideCompany(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "XCOA")
	companyB := mustCreateCompany(t, store, "XCOB")

	_, err := store.CreatePosition(ctx, "test-actor", companyA.ID, "XCPOS1", "Cross Company Position", companyB.ID)
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError for an org_unit outside the company's tree, got %v", err)
	}
	if vErr.Field != "orgUnitId" {
		t.Fatalf("expected field=orgUnitId, got %q", vErr.Field)
	}
}

// TestCreatePosition_AllowsOrgUnitUnderCompany proves the positive case: an org_unit that IS
// under the company (including the company root itself, and a descendant unit) succeeds.
func TestCreatePosition_AllowsOrgUnitUnderCompany(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "XCOOK")
	territory := mustCreateUnit(t, store, "territory", company.ID, "XCOOKTR")

	if _, err := store.CreatePosition(ctx, "test-actor", company.ID, "XCOOKP1", "At Root", company.ID); err != nil {
		t.Fatalf("create position at company root: %v", err)
	}
	if _, err := store.CreatePosition(ctx, "test-actor", company.ID, "XCOOKP2", "Under Territory", territory.ID); err != nil {
		t.Fatalf("create position under a descendant org unit: %v", err)
	}
}

// TestUpdatePosition_RejectsOrgUnitOutsideCompany proves the same store-level check on update:
// moving a position's org_unit_id to a unit outside its own (immutable) company is rejected.
func TestUpdatePosition_RejectsOrgUnitOutsideCompany(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "XCOC")
	companyB := mustCreateCompany(t, store, "XCOD")
	position := mustCreatePosition(t, store, companyA.ID, companyA.ID, "XCPOS2")

	_, err := store.UpdatePosition(ctx, "test-actor", position.ID, "Moved", companyB.ID)
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError for moving a position under another company's org_unit, got %v", err)
	}
	if vErr.Field != "orgUnitId" {
		t.Fatalf("expected field=orgUnitId, got %q", vErr.Field)
	}
}

// TestAssignNow_RejectsCrossCompanyMember proves AssignNow's store-level check: a member from a
// different company than the position's cannot be assigned.
func TestAssignNow_RejectsCrossCompanyMember(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "XCOE")
	companyB := mustCreateCompany(t, store, "XCOF")
	position := mustCreatePosition(t, store, companyA.ID, companyA.ID, "XCPOS3")
	outsideMember := mustCreateMember(t, store, companyB.ID, "XCM1")

	_, err := store.AssignNow(ctx, "test-actor", position.ID, outsideMember.ID)
	if !errors.Is(err, ErrCrossCompanyAssignment) {
		t.Fatalf("expected ErrCrossCompanyAssignment for a cross-company assignment, got %v", err)
	}
}

// TestCreateAndAssign_RejectsCrossCompanyMember proves the same check in the combined
// create+assign path, and that it rolls back the position insert too (one transaction).
func TestCreateAndAssign_RejectsCrossCompanyMember(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "XCOG")
	companyB := mustCreateCompany(t, store, "XCOH")
	outsideMember := mustCreateMember(t, store, companyB.ID, "XCM2")

	_, _, err := store.CreateAndAssign(ctx, "test-actor", companyA.ID, "XCCAA1", "Cross Company CAA", companyA.ID, outsideMember.ID, date("2026-01-01"), nil)
	if !errors.Is(err, ErrCrossCompanyAssignment) {
		t.Fatalf("expected ErrCrossCompanyAssignment, got %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.position WHERE company_id = $1 AND code = 'XCCAA1'`, companyA.ID).Scan(&count); err != nil {
		t.Fatalf("count positions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the position insert to roll back when the cross-company check failed, found %d row(s)", count)
	}
}

// TestConstraints_TriggerRejectsCrossCompanyPosition proves migration 0004's
// position_org_unit_must_be_under_company trigger rejects a direct-SQL write that bypasses the
// store-level check entirely. SKIPS if the migration
// hasn't been applied to this database yet.
func TestConstraints_TriggerRejectsCrossCompanyPosition(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'position_org_unit_must_be_under_company')`).Scan(&exists); err != nil {
		t.Fatalf("check trigger existence: %v", err)
	}
	if !exists {
		t.Skip("migration 0004_cross_company_constraints.sql not applied to this database yet (apply migrations to the test stack first)")
	}

	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	companyA := mustCreateCompany(t, store, "TRIGA")
	companyB := mustCreateCompany(t, store, "TRIGB")

	_, err := admin.Exec(ctx, `INSERT INTO org.position (company_id, code, title, org_unit_id) VALUES ($1, 'TRIGPOS', 'Direct SQL Bypass', $2)`, companyA.ID, companyB.ID)
	if err == nil {
		t.Fatal("expected the position_org_unit_must_be_under_company trigger to reject a direct-SQL cross-company insert")
	}
}

// TestConstraints_TriggerRejectsCrossCompanyAssignment mirrors the proof above for
// assignment_member_must_match_position_company. SKIPS under the same condition.
func TestConstraints_TriggerRejectsCrossCompanyAssignment(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'assignment_member_must_match_position_company')`).Scan(&exists); err != nil {
		t.Fatalf("check trigger existence: %v", err)
	}
	if !exists {
		t.Skip("migration 0004_cross_company_constraints.sql not applied to this database yet (apply migrations to the test stack first)")
	}

	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	companyA := mustCreateCompany(t, store, "TRIGC")
	companyB := mustCreateCompany(t, store, "TRIGD")
	position := mustCreatePosition(t, store, companyA.ID, companyA.ID, "TRIGPOS2")
	outsideMember := mustCreateMember(t, store, companyB.ID, "TRIGM1")

	_, err := admin.Exec(ctx, `INSERT INTO org.position_assignment (position_id, member_id, valid_from) VALUES ($1, $2, '2026-01-01')`, position.ID, outsideMember.ID)
	if err == nil {
		t.Fatal("expected the assignment_member_must_match_position_company trigger to reject a direct-SQL cross-company insert")
	}
}
