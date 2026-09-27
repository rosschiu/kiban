// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzstore "github.com/rosschiu/kiban/internal/authz/store"
)

// unsignedJWTWithSubject builds a syntactically valid but unsigned ("alg":"none") compact JWT
// carrying only a `sub` claim — enough for jwt.ParseInsecure (subjectFromBearer's own parser,
// audit-derivation only, never a signature/authorization check) to extract it.
func unsignedJWTWithSubject(t *testing.T, sub string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return header + "." + payload + "."
}

// doJSONWithAuth is doJSON plus a caller-supplied Authorization header — for tests that need
// actorFor's real-bearer-subject derivation, which every other
// http_more_test.go fixture leaves empty on purpose.
func doJSONWithAuth(t *testing.T, f *httpTestFixture, method, path, body, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	return rec
}

// TestPositionHolder_AssignNow_GrantsTuple proves the assign-NOW store fn: it creates
// the assignment (valid_from=today), grants `position:<id>#holder @ member:<id>#mapped_user`, and
// audits org.assignment.create — the same transaction, all real writes against the live stack.
func TestPositionHolder_AssignNow_GrantsTuple(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH1")
	position := mustCreatePosition(t, store, company.ID, company.ID, "PH1-POS")
	member := mustCreateMember(t, store, company.ID, "PH1-MEM")

	assignment, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID)
	if err != nil {
		t.Fatalf("assign now: %v", err)
	}
	if assignment.ValidFrom.Format("2006-01-02") != mustToday(t, store).Format("2006-01-02") {
		t.Fatalf("valid_from = %v, want today", assignment.ValidFrom)
	}
	if assignment.ValidTo != nil {
		t.Fatalf("valid_to = %v, want nil (open-ended)", assignment.ValidTo)
	}

	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='position' AND object_id=$1 AND relation='holder'
		  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
		position.ID.String(), member.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("holder tuple count = %d, want 1", count)
	}

	var auditAction string
	if err := admin.QueryRow(ctx, `
		SELECT action FROM audit.org__events WHERE subject=$1 ORDER BY id DESC LIMIT 1`,
		"assignment:"+assignment.ID.String(),
	).Scan(&auditAction); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditAction != "org.assignment.create" {
		t.Fatalf("audit action = %q, want org.assignment.create", auditAction)
	}
}

// TestPositionHolder_AssignNow_InactiveMemberRejected proves assign-NOW never assigns an
// inactive member.
func TestPositionHolder_AssignNow_InactiveMemberRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH2")
	position := mustCreatePosition(t, store, company.ID, company.ID, "PH2-POS")
	member, err := store.CreateMember(ctx, "test-actor", company.ID, "PH2-MEM", "Inactive Member", "", false)
	if err != nil {
		t.Fatalf("create inactive member: %v", err)
	}

	_, err = store.AssignNow(ctx, "test-actor", position.ID, member.ID)
	var vErr *ValidationError
	if !errors.As(err, &vErr) || vErr.Field != "memberId" {
		t.Fatalf("expected ErrMemberInactive-shaped ValidationError, got %v", err)
	}
}

// TestPositionHolder_EndAssignment_RevokesTuple proves end-NOW revokes the holder tuple (via the
// SECURITY DEFINER function) in the same transaction as the state change, and a same-day
// handover (end + immediately assign a different member, zero permission-edit surface between)
// leaves exactly the NEW holder's tuple standing.
func TestPositionHolder_EndAssignment_RevokesTuple(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH3")
	position := mustCreatePosition(t, store, company.ID, company.ID, "PH3-POS")
	memberA := mustCreateMember(t, store, company.ID, "PH3-MA")
	memberB := mustCreateMember(t, store, company.ID, "PH3-MB")

	assignmentA, err := store.AssignNow(ctx, "test-actor", position.ID, memberA.ID)
	if err != nil {
		t.Fatalf("assign A: %v", err)
	}
	holderCount := func(memberID string) int {
		var c int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='position' AND object_id=$1 AND relation='holder'
			  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
			position.ID.String(), memberID,
		).Scan(&c); err != nil {
			t.Fatalf("count holder tuple: %v", err)
		}
		return c
	}
	if holderCount(memberA.ID.String()) != 1 {
		t.Fatal("expected memberA's holder tuple after assign")
	}

	if _, err := store.EndAssignment(ctx, "test-actor", assignmentA.ID); err != nil {
		t.Fatalf("end A: %v", err)
	}
	if holderCount(memberA.ID.String()) != 0 {
		t.Fatal("expected memberA's holder tuple revoked after end")
	}

	// Same-day handover: assign B immediately after — zero permission mutations issued directly,
	// only org's own fact-layer calls.
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, memberB.ID); err != nil {
		t.Fatalf("assign B: %v", err)
	}
	if holderCount(memberB.ID.String()) != 1 {
		t.Fatal("expected memberB's holder tuple after same-day handover assign")
	}
}

// TestPositionHolder_CreateAndAssign_FutureDatedRejected proves the v1 stop condition: a
// future-dated create-and-assign window is refused (422), never silently accepted.
func TestPositionHolder_CreateAndAssign_FutureDatedRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH4")
	member := mustCreateMember(t, store, company.ID, "PH4-MEM")

	future := mustToday(t, store).AddDate(0, 0, 30)
	_, _, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "PH4-POS", "Future Position", company.ID, member.ID, future, nil)
	var vErr *ValidationError
	if !errors.As(err, &vErr) || vErr.Field != "validFrom" {
		t.Fatalf("expected a validFrom ValidationError for a future-dated window, got %v", err)
	}
}

// TestPositionHolder_CreateAndAssign_CoversTodayGrantsTuple proves the legacy route DOES grant
// the holder tuple when its (past-or-today, open-or-future) window covers today.
func TestPositionHolder_CreateAndAssign_CoversTodayGrantsTuple(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH5")
	member := mustCreateMember(t, store, company.ID, "PH5-MEM")

	position, _, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "PH5-POS", "Covers Today", company.ID, member.ID, mustToday(t, store).AddDate(0, 0, -10), nil)
	if err != nil {
		t.Fatalf("create and assign: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='position' AND object_id=$1 AND relation='holder'
		  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
		position.ID.String(), member.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("holder tuple count = %d, want 1 (window covers today)", count)
	}
}

// TestPositionHolder_CreateAndAssign_PastClosedWindowGrantsNoTuple proves a WHOLLY past/closed
// window (historical data entry) creates the fact row but confers no CURRENT access.
func TestPositionHolder_CreateAndAssign_PastClosedWindowGrantsNoTuple(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH6")
	member := mustCreateMember(t, store, company.ID, "PH6-MEM")

	past := mustToday(t, store).AddDate(0, 0, -60)
	closed := mustToday(t, store).AddDate(0, 0, -30)
	position, _, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "PH6-POS", "Historical", company.ID, member.ID, past, &closed)
	if err != nil {
		t.Fatalf("create and assign: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='position' AND object_id=$1 AND relation='holder'`,
		position.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if count != 0 {
		t.Fatalf("holder tuple count = %d, want 0 (window is wholly in the past)", count)
	}
}

// TestPositionHolder_DeletePosition_RefusedWhileBound proves a position with a
// live module binding (any tuple naming `position:<id>#holder` as SUBJECT) refuses delete with a
// PositionBoundError carrying the count, and never cascade-revokes the other module's grant.
func TestPositionHolder_DeletePosition_RefusedWhileBound(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH7")
	position := mustCreatePosition(t, store, company.ID, company.ID, "PH7-POS")

	// Simulate a module binding a tier to this position (helpdesk's shape, without needing
	// the helpdesk module here): company_module:<cid>/mod#editor @ position:<id>#holder.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := authzstore.Grant(ctx, tx, "test-actor", "", authzstore.Tuple{
		ObjectType: "company_module", ObjectID: company.ID.String() + "/helpdesk", Relation: "editor",
		SubjectType: "position", SubjectID: position.ID.String(), SubjectRelation: "holder",
	}); err != nil {
		t.Fatalf("grant module binding: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	err = store.DeletePosition(ctx, "test-actor", position.ID)
	var boundErr *PositionBoundError
	if !errors.As(err, &boundErr) {
		t.Fatalf("expected PositionBoundError, got %v", err)
	}
	if boundErr.Count != 1 {
		t.Fatalf("PositionBoundError.Count = %d, want 1", boundErr.Count)
	}

	// The position must still exist (delete refused, not partially applied).
	if _, err := store.GetPosition(ctx, position.ID); err != nil {
		t.Fatalf("expected the position to still exist after a refused delete, got %v", err)
	}

	// The OTHER module's tuple must survive untouched (never cascade-revoked).
	var stillBound int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple WHERE subject_type='position' AND subject_id=$1 AND subject_relation='holder'`,
		position.ID.String(),
	).Scan(&stillBound); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stillBound != 1 {
		t.Fatalf("expected the module binding to survive the refused delete, count=%d", stillBound)
	}
}

// TestPositionHolder_LinkUnlinkUser_TupleLifecycle proves the member-bridge tuple
// (`member:<id>#mapped_user @ user:<kcSub>`) is granted on LinkUser and revoked on UnlinkUser.
func TestPositionHolder_LinkUnlinkUser_TupleLifecycle(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH8")
	member := mustCreateMember(t, store, company.ID, "PH8-MEM")
	mustCreateIdentityUser(t, admin, "kc-sub-ph8")
	checker := &fakeIdentityChecker{exists: map[string]bool{"kc-sub-ph8": true}}

	if _, err := store.LinkUser(ctx, "tester", checker, member.ID, "kc-sub-ph8"); err != nil {
		t.Fatalf("link: %v", err)
	}
	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='member' AND object_id=$1 AND relation='mapped_user'
		  AND subject_type='user' AND subject_id='kc-sub-ph8' AND subject_relation=''`,
		member.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("mapped_user tuple count after link = %d, want 1", count)
	}

	if _, err := store.UnlinkUser(ctx, "tester", member.ID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='member' AND object_id=$1 AND relation='mapped_user'`,
		member.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("mapped_user tuple count after unlink = %d, want 0", count)
	}
}

// TestPositionHolder_Actor_RealBearerSubject proves audit rows carry the real
// verified bearer subject (derived from the JWT's `sub` claim), not "unauthenticated" — an org
// mutation driven through Service.Routes(), not a direct store call, so actorFor's derivation is
// exercised end to end.
func TestPositionHolder_Actor_RealBearerSubject(t *testing.T) {
	f := newAllowAllFixture(t, nil)

	// A minimal unsigned JWT with sub="bearer-sub-407" — ParseInsecure never checks the
	// signature, matching subjectFromBearer's own audit-only, never-authorization-input stance.
	token := unsignedJWTWithSubject(t, "bearer-sub-407")

	req := doJSONWithAuth(t, f, "POST", "/internal/org/units", `{"typeKey":"company","code":"PH9","name":"PH9 Co"}`, "Bearer "+token)
	if req.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", req.Code, req.Body.String())
	}

	admin := adminPool(t)
	var actor string
	if err := admin.QueryRow(context.Background(), `
		SELECT actor FROM audit.org__events WHERE action='org.unit.create' ORDER BY id DESC LIMIT 1`,
	).Scan(&actor); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if actor != "bearer-sub-407" {
		t.Fatalf("audit actor = %q, want bearer-sub-407", actor)
	}
}

// TestPositionHolder_EndAssignment_TwiceIsConflict: ending an already-ended
// assignment is a 409-shaped ErrAssignmentAlreadyEnded that writes nothing — its window is
// unchanged and the holder tuple of the member's NEWER open assignment stays intact.
func TestPositionHolder_EndAssignment_TwiceIsConflict(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "PH9")
	member := mustCreateMember(t, store, company.ID, "PH9-M")
	position, old, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "PH9-POS", "PH9-POS", company.ID, member.ID, mustToday(t, store).AddDate(0, 0, -30), nil)
	if err != nil {
		t.Fatalf("create and assign: %v", err)
	}
	holderCount := func() int {
		var c int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='position' AND object_id=$1 AND relation='holder'
			  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
			position.ID.String(), member.ID.String(),
		).Scan(&c); err != nil {
			t.Fatalf("count holder tuple: %v", err)
		}
		return c
	}

	ended, err := store.EndAssignment(ctx, "test-actor", old.ID)
	if err != nil {
		t.Fatalf("end (first): %v", err)
	}
	if holderCount() != 0 {
		t.Fatal("expected the only open assignment's end to revoke the holder tuple")
	}

	// Re-assign the same member today: a newer open assignment with its own holder tuple.
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, member.ID); err != nil {
		t.Fatalf("assign again: %v", err)
	}
	if holderCount() != 1 {
		t.Fatal("expected the holder tuple after re-assign")
	}

	if _, err := store.EndAssignment(ctx, "test-actor", old.ID); !errors.Is(err, ErrAssignmentAlreadyEnded) {
		t.Fatalf("end (second) = %v, want ErrAssignmentAlreadyEnded", err)
	}
	againRow, err := New(store.pool).GetAssignment(ctx, pgFromUUID(old.ID))
	if err != nil {
		t.Fatalf("get old assignment: %v", err)
	}
	if again := assignmentFromRow(againRow); again.ValidTo == nil || !again.ValidTo.Equal(*ended.ValidTo) {
		t.Fatalf("old window changed: validTo=%v, want %v", again.ValidTo, ended.ValidTo)
	}
	if holderCount() != 1 {
		t.Fatal("re-ending the old assignment must not revoke the newer open assignment's holder tuple")
	}
}
