// SPDX-License-Identifier: Apache-2.0

//go:build live

package org

import (
	"context"
	"testing"
)

// This file proves migration 0007_company_id_immutable.sql closes the reverse-update bypass:
// without it the `kiban_org` runtime role can change an assigned position's company_id, and
// separately an assigned member's company_id, via direct SQL, leaving the assignment invariant
// (position.company_id == member.company_id) violated. Both probes below use direct SQL as
// kiban_org (no store involvement) and assert the reverse-update is rejected — mirrors cross_company_test.go's
// direct-SQL trigger-test pattern. Run with `-tags live` against the isolated kiban-test stack.

// assignmentInvariantHolds reports whether the assignment invariant (a position's company_id
// equals its assigned member's company_id) holds for every row in org.position_assignment.
func assignmentInvariantHolds(t *testing.T, ctx context.Context) bool {
	t.Helper()
	org := orgPool(t)
	var mismatches int
	err := org.QueryRow(ctx, `
		SELECT count(*)
		FROM org.position_assignment pa
		JOIN org.position p ON p.id = pa.position_id
		JOIN org.member m ON m.id = pa.member_id
		WHERE p.company_id IS DISTINCT FROM m.company_id
	`).Scan(&mismatches)
	if err != nil {
		t.Fatalf("check assignment invariant: %v", err)
	}
	return mismatches == 0
}

// TestCompanyIdImmutable_PositionUpdateRejected: as
// kiban_org, directly UPDATE an assigned position's company_id to a different company. Before
// migration 0007 is applied this succeeds and breaks the assignment invariant
// (position.company_id != member.company_id) — this test asserts it is REJECTED and the
// invariant still holds.
func TestCompanyIdImmutable_PositionUpdateRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "IMMA")
	companyB := mustCreateCompany(t, store, "IMMB")
	position := mustCreatePosition(t, store, companyA.ID, companyA.ID, "IMMPOS1")
	member := mustCreateMember(t, store, companyA.ID, "IMMM1")
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID); err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	// company_id AND org_unit_id are moved together to a
	// unit actually under company B, so migration 0004's position_org_unit_must_be_under_company
	// trigger (org_unit_id must sit beneath company_id) is satisfied and does NOT catch this —
	// only 0007's immutability trigger does. Setting company_id alone (leaving org_unit_id under
	// company A) would already be caught by 0004 and wouldn't prove 0007 is needed.
	org := orgPool(t)
	_, err := org.Exec(ctx, `UPDATE org.position SET company_id = $1, org_unit_id = $1 WHERE id = $2`, companyB.ID, position.ID)
	if err == nil {
		t.Fatal("expected the position_company_id_immutable trigger to reject a direct-SQL company_id change on an assigned position")
	}

	if !assignmentInvariantHolds(t, ctx) {
		t.Fatal("assignment invariant violated: a position's company_id no longer matches its assigned member's company_id")
	}
}

// TestCompanyIdImmutable_MemberUpdateRejected: as
// kiban_org, directly UPDATE an assigned member's company_id to a different company. Before
// migration 0007 is applied this succeeds and breaks the assignment invariant — this test
// asserts it is REJECTED and the invariant still holds.
func TestCompanyIdImmutable_MemberUpdateRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "IMMC")
	companyB := mustCreateCompany(t, store, "IMMD")
	position := mustCreatePosition(t, store, companyA.ID, companyA.ID, "IMMPOS2")
	member := mustCreateMember(t, store, companyA.ID, "IMMM2")
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID); err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	org := orgPool(t)
	_, err := org.Exec(ctx, `UPDATE org.member SET company_id = $1 WHERE id = $2`, companyB.ID, member.ID)
	if err == nil {
		t.Fatal("expected the member_company_id_immutable trigger to reject a direct-SQL company_id change on an assigned member")
	}

	if !assignmentInvariantHolds(t, ctx) {
		t.Fatal("assignment invariant violated: a member's company_id no longer matches their assigned position's company_id")
	}
}

// TestCompanyIdImmutable_EqualValueWriteAllowed proves the harmless case: a
// query that lists company_id in its SET clause with the SAME value the row already has must
// still succeed (NEW.company_id IS DISTINCT FROM OLD.company_id is false, the trigger is a
// no-op).
func TestCompanyIdImmutable_EqualValueWriteAllowed(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "IMME")
	position := mustCreatePosition(t, store, company.ID, company.ID, "IMMPOS3")
	member := mustCreateMember(t, store, company.ID, "IMMM3")

	org := orgPool(t)
	if _, err := org.Exec(ctx, `UPDATE org.position SET company_id = $1 WHERE id = $2`, company.ID, position.ID); err != nil {
		t.Fatalf("expected an equal-value company_id write on org.position to succeed, got %v", err)
	}
	if _, err := org.Exec(ctx, `UPDATE org.member SET company_id = $1 WHERE id = $2`, company.ID, member.ID); err != nil {
		t.Fatalf("expected an equal-value company_id write on org.member to succeed, got %v", err)
	}
}
