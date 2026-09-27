// SPDX-License-Identifier: Apache-2.0

// Org edge cases: tenant-timezone "today", delete pre-checks in-transaction + FK-on-delete
// 409, pagination bounds, literal `q`, group-member edge cases, default grants on company
// activation.
package org

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// setTenantTimezone writes platform.tenant_defaults.timezone (registry-owned; the admin pool is
// the owner) and restores UTC on cleanup.
func setTenantTimezone(t *testing.T, tz string) {
	t.Helper()
	admin := adminPool(t)
	if _, err := admin.Exec(context.Background(), `UPDATE platform.tenant_defaults SET timezone = $1 WHERE tenant_id = 'default'`, tz); err != nil {
		t.Fatalf("set tenant timezone: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), `UPDATE platform.tenant_defaults SET timezone = 'UTC' WHERE tenant_id = 'default'`) //nolint:errcheck
	})
}

// TestStore_Today_TenantTimezone: the calendar date is taken in tenant_defaults.timezone,
// so at 10:30Z on Jan 1 a UTC+14 tenant is already on Jan 2 and a UTC-11 tenant still on Dec 31.
func TestStore_Today_TenantTimezone(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	store.now = func() time.Time { return time.Date(2026, 1, 1, 10, 30, 0, 0, time.UTC) }

	for _, tc := range []struct{ tz, want string }{
		{"UTC", "2026-01-01"},
		{"Pacific/Kiritimati", "2026-01-02"},
		{"Pacific/Pago_Pago", "2025-12-31"},
	} {
		setTenantTimezone(t, tc.tz)
		got := mustToday(t, store)
		if got.Format("2006-01-02") != tc.want {
			t.Fatalf("tz %s: today = %s, want %s", tc.tz, got.Format("2006-01-02"), tc.want)
		}
	}

	// The stamped fact uses the same clock: assign-NOW in the UTC+14 zone stores Jan 2.
	setTenantTimezone(t, "Pacific/Kiritimati")
	company := mustCreateCompany(t, store, "TZCO")
	member := mustCreateMember(t, store, company.ID, "TZM")
	position := mustCreatePosition(t, store, company.ID, company.ID, "TZP")
	assignment, err := store.AssignNow(context.Background(), "test-actor", position.ID, member.ID)
	if err != nil {
		t.Fatalf("AssignNow: %v", err)
	}
	if got := assignment.ValidFrom.Format("2006-01-02"); got != "2026-01-02" {
		t.Fatalf("validFrom = %s, want 2026-01-02", got)
	}

	setTenantTimezone(t, "Not/AZone")
	if _, err := store.today(context.Background(), store.pool); err == nil {
		t.Fatal("an unloadable tenant timezone must be an error, not a silent UTC fallback")
	}
}

// TestStore_DeleteOrgUnit_RacingChildInsert: a child insert racing the delete never
// leaves both succeeding — the FOR UPDATE lock serialises the FK's KEY SHARE, so either the
// pre-check sees the child (422) or the insert fails against the deleted parent.
func TestStore_DeleteOrgUnit_RacingChildInsert(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		company := mustCreateCompany(t, store, "RACE"+string(rune('A'+i)))
		var wg sync.WaitGroup
		var delErr, insErr error
		wg.Add(2)
		go func() { defer wg.Done(); delErr = store.DeleteOrgUnit(ctx, "test-actor", company.ID) }()
		go func() {
			defer wg.Done()
			_, insErr = store.CreateOrgUnit(ctx, "test-actor", "territory", &company.ID, "CHILD", "Child Unit", true)
		}()
		wg.Wait()
		if delErr == nil && insErr == nil {
			t.Fatalf("iteration %d: delete AND child insert both succeeded", i)
		}
		var refErr *ReferencedError
		if insErr == nil && !errors.Is(delErr, ErrOrgUnitHasChildren) && !errors.As(delErr, &refErr) {
			t.Fatalf("iteration %d: child committed but delete failed with %v, want has-children/referenced", i, delErr)
		}
		if delErr == nil {
			// Insert lost: the parent is gone.
			var vErr *ValidationError
			if !errors.As(insErr, &vErr) {
				t.Fatalf("iteration %d: delete committed but insert failed with %v, want a ValidationError (FK)", i, insErr)
			}
		}
	}
}

// TestHTTP_Delete_StillReferenced_409: an FK violation on DELETE is a 409 CONFLICT naming
// the referencing table — not a 422 "referenced row does not exist".
func TestHTTP_Delete_StillReferenced_409(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	ctx := context.Background()
	company := mustCreateCompany(t, store, "REF409")
	position := mustCreatePosition(t, store, company.ID, company.ID, "REF-P")

	// A unit with a position but no children/members (the pre-checks pass) → FK → 409.
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/units/"+company.ID.String(), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete unit: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "CONFLICT" || errObj["details"].(map[string]any)["field"] != "position" {
		t.Fatalf("delete unit: error = %v, want CONFLICT field=position", errObj)
	}

	// A position with assignment history → FK from position_assignment → 409.
	member := mustCreateMember(t, store, company.ID, "REF-M")
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID); err != nil {
		t.Fatalf("AssignNow: %v", err)
	}
	rec = doJSON(t, f, http.MethodDelete, "/internal/org/positions/"+position.ID.String(), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete position: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	errObj = decodeEnvelope(t, rec)["error"].(map[string]any)
	if errObj["code"] != "CONFLICT" || errObj["details"].(map[string]any)["field"] != "position_assignment" {
		t.Fatalf("delete position: error = %v, want CONFLICT field=position_assignment", errObj)
	}
	// Nothing was deleted or revoked by the refused attempts.
	var anchors int
	if err := adminPool(t).QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='position' AND object_id=$1 AND relation='company'`, position.ID.String()).Scan(&anchors); err != nil {
		t.Fatal(err)
	}
	if anchors != 1 {
		t.Fatalf("position company anchor count after refused delete = %d, want 1", anchors)
	}
}

// TestHTTP_Pagination_OverLimit_400: page > 10 000 or pageSize > 100 is a 400
// VALIDATION_ERROR naming the field; the int32-overflowing input the review cites is one of them.
func TestHTTP_Pagination_OverLimit_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "PAGE400")
	base := "/internal/org/companies/" + company.ID.String()
	for _, tc := range []struct{ path, field string }{
		{base + "/positions?page=10001", "page"},
		{base + "/positions?page=21474838&pageSize=100", "page"},
		{base + "/positions?pageSize=101", "pageSize"},
		{base + "/groups?page=10001", "page"},
		{"/internal/org/positions?companyId=" + company.ID.String() + "&pageSize=101", "pageSize"},
	} {
		rec := doJSON(t, f, http.MethodGet, tc.path, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400, body=%s", tc.path, rec.Code, rec.Body.String())
		}
		errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
		if errObj["code"] != "VALIDATION_ERROR" || errObj["details"].(map[string]any)["field"] != tc.field {
			t.Fatalf("%s: error = %v, want VALIDATION_ERROR field=%s", tc.path, errObj, tc.field)
		}
	}
	// The maximum itself is accepted.
	rec := doJSON(t, f, http.MethodGet, base+"/positions?page=10000&pageSize=100", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("page=10000: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestStore_MemberDirectory_QIsLiteral: `%`, `_` and `\` in q match themselves only.
func TestStore_MemberDirectory_QIsLiteral(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()
	company := mustCreateCompany(t, store, "QLIT")
	for _, m := range []struct{ code, name string }{{"ALICE", "Alice"}, {"BOB", "Bob"}, {"PCT", "50% off_deal\\x"}} {
		if _, err := store.CreateMember(ctx, "test-actor", company.ID, m.code, m.name, "", true); err != nil {
			t.Fatalf("create %s: %v", m.code, err)
		}
	}
	for q, want := range map[string]int{"%": 1, "_": 1, `\`: 1, "% off": 1, "ali": 1, "": 3} {
		_, total, err := store.MemberDirectory(ctx, company.ID, q, 1, 25)
		if err != nil {
			t.Fatalf("q=%q: %v", q, err)
		}
		if total != want {
			t.Fatalf("q=%q: total = %d, want %d", q, total, want)
		}
	}
}

// TestGroupMember_EdgeCases: removing a non-member is a 404 with no audit row and no
// revoke ledger row; re-adding an existing member returns the STORED addedBy/addedAt and writes
// no second audit row.
func TestGroupMember_EdgeCases(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	admin := adminPool(t)
	ctx := context.Background()
	company := mustCreateCompany(t, store, "GMEDGE")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")
	member := mustCreateMember(t, store, company.ID, "ALICE")

	rec := doJSON(t, f, http.MethodDelete, "/internal/org/groups/"+group.ID.String()+"/members/"+member.ID.String(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("remove non-member: status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit.org__events WHERE action='org.group.member_remove'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit rows for a no-op remove = %d (err %v), want 0", n, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.grant_ledger WHERE object_type='group' AND object_id=$1 AND relation='member'`, group.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("grant_ledger rows for a no-op remove = %d (err %v), want 0", n, err)
	}

	first, err := store.AddGroupMember(ctx, "first-actor", group.ID, member.ID)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}
	again, err := store.AddGroupMember(ctx, "second-actor", group.ID, member.ID)
	if err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if again.AddedBy != "first-actor" || !again.AddedAt.Equal(first.AddedAt) {
		t.Fatalf("idempotent add returned addedBy=%q addedAt=%v, want the stored first-actor/%v", again.AddedBy, again.AddedAt, first.AddedAt)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit.org__events WHERE action='org.group.member_add'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("member_add audit rows = %d (err %v), want 1", n, err)
	}
	if _, err := store.AddGroupMember(ctx, "x", group.ID, uuid.New()); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("add unknown member: %v, want ErrMemberNotFound", err)
	}
}

// TestUpdateOrgUnit_ActivatingCompanyWritesDefaultGrants: a company created inactive gets
// its enabled modules' default grants when it is activated, in the activation transaction.
func TestUpdateOrgUnit_ActivatingCompanyWritesDefaultGrants(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	ctx := context.Background()

	const moduleKey = "activation_widget"
	if _, err := admin.Exec(ctx, `
		INSERT INTO platform.module_catalog (module_key, display_name, scope_type, base_path, health_path, port, license_class, manifest_version)
		VALUES ($1, 'Activation Widget', 'company', '/api/activation-widget', '/health', 8398, 'foundation', '0.1.0')
		ON CONFLICT (module_key) DO NOTHING`, moduleKey); err != nil {
		t.Fatalf("insert module_catalog fixture: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO platform.module_installation (module_key, installed, enabled) VALUES ($1, true, true)
		ON CONFLICT (module_key) DO UPDATE SET installed=true, enabled=true`, moduleKey); err != nil {
		t.Fatalf("insert module_installation fixture: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE module_key=$1`, moduleKey)                                          //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey)        //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey) //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM platform.module_installation WHERE module_key=$1`, moduleKey)                                 //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM platform.module_catalog WHERE module_key=$1`, moduleKey)                                      //nolint:errcheck
	})

	store := newTestStore(t)
	unit, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "ACTCO", "Activation Inactive Co", false)
	if err != nil {
		t.Fatalf("CreateOrgUnit(inactive): %v", err)
	}
	countTuples := func() int {
		var n int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND subject_type='system' AND subject_id='platform'`,
			unit.ID.String()+"/"+moduleKey).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := countTuples(); n != 0 {
		t.Fatalf("inactive company default tuple count = %d, want 0", n)
	}
	if _, err := store.UpdateOrgUnit(ctx, "test-actor", unit.ID, nil, unit.Code, unit.Name, true); err != nil {
		t.Fatalf("UpdateOrgUnit(activate): %v", err)
	}
	if n := countTuples(); n != 1 {
		t.Fatalf("activated company default tuple count = %d, want 1", n)
	}
	// Default-ONCE: deactivate + reactivate does not duplicate anything.
	for _, active := range []bool{false, true} {
		if _, err := store.UpdateOrgUnit(ctx, "test-actor", unit.ID, nil, unit.Code, unit.Name, active); err != nil {
			t.Fatalf("UpdateOrgUnit(%v): %v", active, err)
		}
	}
	if n := countTuples(); n != 1 {
		t.Fatalf("re-activated company default tuple count = %d, want 1", n)
	}
}
