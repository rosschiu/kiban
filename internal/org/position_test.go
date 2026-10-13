// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
)

// TestPosition_CRUD proves basic position CRUD.
func TestPosition_CRUD(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "POS1")
	position := mustCreatePosition(t, store, company.ID, company.ID, "ENG-LEAD")

	got, err := store.GetPosition(ctx, position.ID)
	if err != nil {
		t.Fatalf("get position: %v", err)
	}
	if got.Title != "Test Position ENG-LEAD" {
		t.Fatalf("unexpected position: %+v", got)
	}

	updated, err := store.UpdatePosition(ctx, "test-actor", position.ID, "Engineering Lead", company.ID)
	if err != nil {
		t.Fatalf("update position: %v", err)
	}
	if updated.Title != "Engineering Lead" {
		t.Fatalf("update not applied: %+v", updated)
	}

	positions, total, err := store.ListPositions(ctx, company.ID, 1, 25)
	if err != nil {
		t.Fatalf("list positions: %v", err)
	}
	if total != 1 || len(positions) != 1 {
		t.Fatalf("expected 1 position, got total=%d len=%d", total, len(positions))
	}

	if err := store.DeletePosition(ctx, "test-actor", position.ID); err != nil {
		t.Fatalf("delete position: %v", err)
	}
	if _, err := store.GetPosition(ctx, position.ID); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("expected ErrPositionNotFound after delete, got %v", err)
	}
}

// TestPosition_CreateAndAssign_Success proves the combined create+assign operation creates
// both rows atomically.
func TestPosition_CreateAndAssign_Success(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "POS2")
	member := mustCreateMember(t, store, company.ID, "M700")

	position, assignment, err := store.CreateAndAssign(ctx, "actor", company.ID, "CFO", "Chief Financial Officer", company.ID, member.ID, date("2026-01-01"), nil)
	if err != nil {
		t.Fatalf("create and assign: %v", err)
	}
	if position.Code != "CFO" {
		t.Fatalf("unexpected position: %+v", position)
	}
	if assignment.PositionID != position.ID || assignment.MemberID != member.ID {
		t.Fatalf("unexpected assignment: %+v", assignment)
	}

	holder, err := store.AssignmentOnDate(ctx, position.ID, date("2026-06-01"))
	if err != nil {
		t.Fatalf("assignment on date: %v", err)
	}
	if holder.MemberID != member.ID {
		t.Fatalf("unexpected holder: %+v", holder)
	}
}

// TestPosition_CreateAndAssign_RollsBackOnAssignFailure proves failure at assign rolls
// back the position — here the assign step
// fails because memberID doesn't exist (a foreign-key violation), and the position must not be
// left behind.
func TestPosition_CreateAndAssign_RollsBackOnAssignFailure(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "POS3")
	ghostMemberID := mustCreateCompany(t, store, "POS3-GHOST").ID // any uuid with no org.member row

	_, _, err := store.CreateAndAssign(ctx, "actor", company.ID, "CTO", "Chief Technology Officer", company.ID, ghostMemberID, date("2026-01-01"), nil)
	if err == nil {
		t.Fatal("expected CreateAndAssign to fail when memberId doesn't reference a real member")
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.position WHERE company_id = $1 AND code = 'CTO'`, company.ID).Scan(&count); err != nil {
		t.Fatalf("count positions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the position insert to roll back when the assign step failed, found %d row(s)", count)
	}
}

// TestPosition_EndAssignment_AndValidityWindow proves ending an assignment closes its window,
// and AssignmentOnDate correctly answers "who holds position P on date D" across that boundary.
func TestPosition_EndAssignment_AndValidityWindow(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "POS4")
	memberA := mustCreateMember(t, store, company.ID, "MVA")
	memberB := mustCreateMember(t, store, company.ID, "MVB")

	past := mustToday(t, store).AddDate(0, 0, -30)
	position, assignmentA, err := store.CreateAndAssign(ctx, "test-actor", company.ID, "VP-SALES", "VP-SALES", company.ID, memberA.ID, past, nil)
	if err != nil {
		t.Fatalf("create assignment A: %v", err)
	}

	// EndAssignment is end-NOW only — it always closes as of today (half-open
	// exclusive).
	ended, err := store.EndAssignment(ctx, "test-actor", assignmentA.ID)
	if err != nil {
		t.Fatalf("end assignment: %v", err)
	}
	wantValidTo := mustToday(t, store).Format("2006-01-02")
	if ended.ValidTo == nil || ended.ValidTo.Format("2006-01-02") != wantValidTo {
		t.Fatalf("assignment not ended correctly (want valid_to=%s): %+v", wantValidTo, ended)
	}

	// The same-day handover: B starts TODAY, the exact (exclusive) boundary A's window just
	// closed on — half-open semantics mean these do NOT overlap.
	if _, err := store.AssignNow(ctx, "test-actor", position.ID, memberB.ID); err != nil {
		t.Fatalf("create assignment B: %v", err)
	}

	beforeHolder, err := store.AssignmentOnDate(ctx, position.ID, past.AddDate(0, 0, 1))
	if err != nil || beforeHolder.MemberID != memberA.ID {
		t.Fatalf("expected memberA to hold the position the day after the window opened: %+v, err=%v", beforeHolder, err)
	}
	afterHolder, err := store.AssignmentOnDate(ctx, position.ID, mustToday(t, store))
	if err != nil || afterHolder.MemberID != memberB.ID {
		t.Fatalf("expected memberB to hold the position today: %+v, err=%v", afterHolder, err)
	}
	_, err = store.AssignmentOnDate(ctx, position.ID, past.AddDate(0, 0, -365))
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("expected ErrAssignmentNotFound for a date long before any assignment, got %v", err)
	}
}

// TestPosition_AssignNow_HeldNamesCurrentHolder: a second assign while the position has a holder
// today is refused with PositionHeldError naming that assignment and member, and nothing is
// written; after the holder's tenure ends the same assign succeeds.
func TestPosition_AssignNow_HeldNamesCurrentHolder(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "HELD")
	first := mustCreateMember(t, store, company.ID, "M801")
	second := mustCreateMember(t, store, company.ID, "M802")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")

	current, err := store.AssignNow(ctx, "actor", position.ID, first.ID)
	if err != nil {
		t.Fatalf("first assign: %v", err)
	}
	_, err = store.AssignNow(ctx, "actor", position.ID, second.ID)
	var held *PositionHeldError
	if !errors.As(err, &held) {
		t.Fatalf("second assign: got %v, want PositionHeldError", err)
	}
	if held.AssignmentID != current.ID || held.MemberID != first.ID {
		t.Fatalf("held = %+v, want assignment %s member %s", held, current.ID, first.ID)
	}
	var n int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM org.position_assignment WHERE position_id = $1`, pgFromUUID(position.ID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("assignments after refusal = %d, want 1", n)
	}
	if _, err := store.EndAssignment(ctx, "actor", current.ID); err != nil {
		t.Fatalf("end: %v", err)
	}
	if _, err := store.AssignNow(ctx, "actor", position.ID, second.ID); err != nil {
		t.Fatalf("assign after end: %v", err)
	}
}
