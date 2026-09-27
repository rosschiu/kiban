// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// companyMemberTupleCount counts `company:<companyId>#member @ member:<memberId>#mapped_user`.
func companyMemberTupleCount(t *testing.T, companyID, memberID uuid.UUID) int {
	t.Helper()
	var c int
	if err := adminPool(t).QueryRow(context.Background(), `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company' AND object_id=$1 AND relation='member'
		  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
		companyID.String(), memberID.String(),
	).Scan(&c); err != nil {
		t.Fatalf("count company member tuple: %v", err)
	}
	return c
}

// TestCompanyMember_TupleLifecycle proves the membership fact follows the member row's active
// flag: granted on active create, revoked on deactivate, re-granted on reactivate, never
// written for an inactive create.
func TestCompanyMember_TupleLifecycle(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "CM1")
	member := mustCreateMember(t, store, company.ID, "CM1-MEM")
	if got := companyMemberTupleCount(t, company.ID, member.ID); got != 1 {
		t.Fatalf("after active create: tuple count = %d, want 1", got)
	}

	if _, err := store.UpdateMember(ctx, "test-actor", member.ID, member.DisplayName, "", false); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if got := companyMemberTupleCount(t, company.ID, member.ID); got != 0 {
		t.Fatalf("after deactivate: tuple count = %d, want 0", got)
	}

	if _, err := store.UpdateMember(ctx, "test-actor", member.ID, member.DisplayName, "", true); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if got := companyMemberTupleCount(t, company.ID, member.ID); got != 1 {
		t.Fatalf("after reactivate: tuple count = %d, want 1", got)
	}

	// A no-flip update (still active) must not duplicate or drop the fact.
	if _, err := store.UpdateMember(ctx, "test-actor", member.ID, "Renamed", "", true); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := companyMemberTupleCount(t, company.ID, member.ID); got != 1 {
		t.Fatalf("after rename: tuple count = %d, want 1", got)
	}

	inactive, err := store.CreateMember(ctx, "test-actor", company.ID, "CM1-INACT", "Inactive", "", false)
	if err != nil {
		t.Fatalf("create inactive member: %v", err)
	}
	if got := companyMemberTupleCount(t, company.ID, inactive.ID); got != 0 {
		t.Fatalf("after inactive create: tuple count = %d, want 0", got)
	}
}

// TestCompanyMember_EngineAnswersCompanyModuleMember proves the base model's
// `company_module#member = this or (member from company) or admin` answers true for a user
// exactly while their member row is active AND linked, and false against another company's
// module. The `company_module:<c>/<m>#company @ company:<c>` anchor is seeded here explicitly:
// in production authz/store.EnsureDefaultGrant writes it for every enabled module when a
// company is created, but this test's registry has no `timesheet` row, so the
// company-create hook writes nothing for that pair.
func TestCompanyMember_EngineAnswersCompanyModuleMember(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "CM2A")
	companyB := mustCreateCompany(t, store, "CM2B")
	moduleA := companyA.ID.String() + "/timesheet"
	moduleB := companyB.ID.String() + "/timesheet"
	for _, pair := range [][2]string{{moduleA, companyA.ID.String()}, {moduleB, companyB.ID.String()}} {
		if _, err := admin.Exec(ctx, `
			INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ('company_module', $1, 'company', 'company', $2, '') ON CONFLICT DO NOTHING`, pair[0], pair[1]); err != nil {
			t.Fatalf("seed company_module anchor: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id IN ($1, $2)`, moduleA, moduleB)
	})

	member := mustCreateMember(t, store, companyA.ID, "CM2-MEM")
	const kcSub = "kc-sub-cm2"
	mustCreateIdentityUser(t, admin, kcSub)
	checker := &fakeIdentityChecker{exists: map[string]bool{kcSub: true}}

	en := &engine.Engine{Pool: admin, Model: engine.BaseModel}
	isMember := func(moduleObjectID string) bool {
		t.Helper()
		ok, err := en.Check(ctx, "company_module", moduleObjectID, "member", "user", kcSub)
		if err != nil {
			t.Fatalf("engine check: %v", err)
		}
		return ok
	}

	if isMember(moduleA) {
		t.Fatal("active but unlinked member: want false")
	}
	if _, err := store.LinkUser(ctx, "test-actor", checker, member.ID, kcSub); err != nil {
		t.Fatalf("link: %v", err)
	}
	if !isMember(moduleA) {
		t.Fatal("active + linked member: want true on own company's module")
	}
	if isMember(moduleB) {
		t.Fatal("active + linked member of company A: want false on company B's module")
	}

	if _, err := store.UpdateMember(ctx, "test-actor", member.ID, member.DisplayName, "", false); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if isMember(moduleA) {
		t.Fatal("deactivated member: want false")
	}
	if _, err := store.UpdateMember(ctx, "test-actor", member.ID, member.DisplayName, "", true); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if !isMember(moduleA) {
		t.Fatal("reactivated member: want true")
	}

	if _, err := store.UnlinkUser(ctx, "test-actor", member.ID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if isMember(moduleA) {
		t.Fatal("active but unlinked (after unlink) member: want false")
	}
}
