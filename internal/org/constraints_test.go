// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
)

// TestConstraints_DuplicateUserLinkRejected proves UNIQUE(company_id, user_id)
// WHERE user_id IS NOT NULL rejects a second member in the same company linking the same
// identity user.
func TestConstraints_DuplicateUserLinkRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "ACME")
	userID := mustCreateIdentityUser(t, admin, "kc-sub-dup")

	m1 := mustCreateMember(t, store, company.ID, "M1")
	m2 := mustCreateMember(t, store, company.ID, "M2")

	if _, err := admin.Exec(ctx, `UPDATE org.member SET user_id = $1 WHERE id = $2`, userID, m1.ID); err != nil {
		t.Fatalf("link m1 to user: %v", err)
	}

	_, err := admin.Exec(ctx, `UPDATE org.member SET user_id = $1 WHERE id = $2`, userID, m2.ID)
	if err == nil {
		t.Fatal("expected a unique-violation linking a second member in the same company to the same user, got nil error")
	}
}

// TestConstraints_OverlappingAssignmentRejected proves the exclusion constraint: two
// assignments on the same position with overlapping validity windows are rejected.
func TestConstraints_OverlappingAssignmentRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "OVCO")
	memberA := mustCreateMember(t, store, company.ID, "MA")
	memberB := mustCreateMember(t, store, company.ID, "MB")

	position, first, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "POS1", "POS1", company.ID, memberA.ID, date("2026-01-01"), nil)
	if err != nil {
		t.Fatalf("create first assignment: %v", err)
	}

	_, err = store.AssignNow(ctx, "test-actor", position.ID, memberB.ID)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for an overlapping open-ended assignment, got %v", err)
	}

	// A non-overlapping window (ends before the first assignment... impossible since the first
	// is open-ended, so instead prove a window that starts after an explicit end succeeds).
	// EndAssignment is end-NOW only — it closes first's window as of today (half-open
	// exclusive), so a new assignment starting TODAY (the same-day handover case) no longer
	// overlaps it.
	if _, err := store.EndAssignment(ctx, "test-actor", first.ID); err != nil {
		t.Fatalf("end first assignment: %v", err)
	}
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, memberB.ID); err != nil {
		t.Fatalf("expected the now-non-overlapping assignment to succeed, got %v", err)
	}
}

// TestConstraints_SecondCompanyTypeRejected proves the partial unique index enforcing exactly
// ONE org_unit_type row with is_company=true.
func TestConstraints_SecondCompanyTypeRejected(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	_, err := admin.Exec(ctx, `INSERT INTO org.org_unit_type (key, label, is_company) VALUES ('company2', 'Company Two', true)`)
	if err == nil {
		admin.Exec(ctx, `DELETE FROM org.org_unit_type WHERE key = 'company2'`) //nolint:errcheck // cleanup best-effort
		t.Fatal("expected a unique-violation inserting a second is_company=true org_unit_type row, got nil error")
	}
}

// TestConstraints_CompanyCodeNormalizationAnd422 proves the code-normalization rule
// (trim/upper/spaces→-) and that an invalid code surfaces as a 422-shaped ValidationError
// {field: "code"}.
func TestConstraints_CompanyCodeNormalizationAnd422(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	unit, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "  acme corp  ", "Acme Corp", true)
	if err != nil {
		t.Fatalf("create with normalizable code: %v", err)
	}
	if unit.Code != "ACME-CORP" {
		t.Fatalf("code not normalized: got %q, want ACME-CORP", unit.Code)
	}

	_, err = store.CreateOrgUnit(ctx, "test-actor", "company", nil, "a", "Too Short Code", true)
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError for an invalid code, got %v", err)
	}
	if vErr.Field != "code" {
		t.Fatalf("expected field=code, got %q", vErr.Field)
	}
}
