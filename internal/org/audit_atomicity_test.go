// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
)

// brokenAuditStore builds a Store whose audit writer targets a syntactically valid
// (audit.<module>__<name>) but non-existent table, so every Record call fails at the database —
// a real driver error, not a mock — used to prove the fail-closed rule: an
// audit failure must roll back the state change in the SAME transaction, for every org mutation
// handler refactored onto the begin-tx -> state write -> audit append -> commit shape.
func brokenAuditStore(t *testing.T) *Store {
	t.Helper()
	auditWriter, err := audit.NewWriter("audit.org__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	return NewStore(orgPool(t), auditWriter)
}

// TestCreateOrgUnit_AuditFailureRollsBack proves the fail-closed rule for org units: if
// the audit append fails, the org_unit insert must not survive.
func TestCreateOrgUnit_AuditFailureRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := brokenAuditStore(t)
	ctx := context.Background()

	_, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "AUDITFAIL1", "Audit Fail Co", true)
	if err == nil {
		t.Fatal("expected CreateOrgUnit to fail when the audit append fails")
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.org_unit WHERE code = 'AUDITFAIL1'`).Scan(&count); err != nil {
		t.Fatalf("count org units: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the org_unit insert to roll back when the audit append failed, found %d row(s)", count)
	}
}

// TestUpdateOrgUnit_AuditFailureRollsBack proves the same rule for updates: the row must remain
// at its pre-update values.
func TestUpdateOrgUnit_AuditFailureRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	goodStore := newTestStore(t)
	ctx := context.Background()

	unit, err := goodStore.CreateOrgUnit(ctx, "test-actor", "company", nil, "AUDITFAIL2", "Original Name", true)
	if err != nil {
		t.Fatalf("create org unit: %v", err)
	}

	brokenStore := brokenAuditStore(t)
	_, err = brokenStore.UpdateOrgUnit(ctx, "test-actor", unit.ID, nil, "AUDITFAIL2", "Changed Name", true)
	if err == nil {
		t.Fatal("expected UpdateOrgUnit to fail when the audit append fails")
	}

	got, err := goodStore.GetOrgUnit(ctx, unit.ID)
	if err != nil {
		t.Fatalf("get org unit: %v", err)
	}
	if got.Name != "Original Name" {
		t.Fatalf("expected the update to roll back when the audit append failed, got name=%q", got.Name)
	}
}

// TestCreatePosition_AuditFailureRollsBack proves the same rule for positions.
func TestCreatePosition_AuditFailureRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	goodStore := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, goodStore, "AUDITFAIL3")

	brokenStore := brokenAuditStore(t)
	_, err := brokenStore.CreatePosition(ctx, "test-actor", company.ID, "AFPOS1", "Audit Fail Position", company.ID)
	if err == nil {
		t.Fatal("expected CreatePosition to fail when the audit append fails")
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.position WHERE code = 'AFPOS1'`).Scan(&count); err != nil {
		t.Fatalf("count positions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the position insert to roll back when the audit append failed, found %d row(s)", count)
	}
}

// TestEndAssignment_AuditFailureRollsBack proves the same rule for the assignment.end mutation:
// valid_to must remain unset (still open-ended) when the audit append fails.
func TestEndAssignment_AuditFailureRollsBack(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	goodStore := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, goodStore, "AUDITFAIL4")
	member := mustCreateMember(t, goodStore, company.ID, "AFM1")
	_, assignment, err := goodStore.CreateAndAssign(ctx, "test-actor", company.ID, "AFPOS2", "AFPOS2", company.ID, member.ID, date("2026-01-01"), nil)
	if err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	brokenStore := brokenAuditStore(t)
	_, err = brokenStore.EndAssignment(ctx, "test-actor", assignment.ID)
	if err == nil {
		t.Fatal("expected EndAssignment to fail when the audit append fails")
	}

	var validTo *string
	if err := admin.QueryRow(ctx, `SELECT valid_to::text FROM org.position_assignment WHERE id = $1`, assignment.ID).Scan(&validTo); err != nil {
		t.Fatalf("query assignment: %v", err)
	}
	if validTo != nil {
		t.Fatalf("expected valid_to to remain NULL (open-ended) when the audit append failed, got %v", *validTo)
	}
}
