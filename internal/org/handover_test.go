// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestHandover_EndsAndAssignsInOneTransaction: the old holder's assignment ends today, the new
// one starts today, the holder tuple moves, both audit events carry one handoverId; a repeat
// for the same member changes nothing; a stale expectedAssignmentId is refused with the current
// holder; an empty position is a validation error.
func TestHandover_EndsAndAssignsInOneTransaction(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "HAND")
	dave := mustCreateMember(t, store, company.ID, "M901")
	erin := mustCreateMember(t, store, company.ID, "M902")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")

	// Empty position: assign, never hand over.
	var vErr *ValidationError
	if _, _, err := store.Handover(ctx, "actor", position.ID, dave.ID, nil); !errors.As(err, &vErr) {
		t.Fatalf("handover on an empty position: %v, want ValidationError", err)
	}
	first, err := store.AssignNow(ctx, "actor", position.ID, dave.ID)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	// Stale expectation names the current holder.
	wrong := erin.ID
	var held *PositionHeldError
	if _, _, err := store.Handover(ctx, "actor", position.ID, erin.ID, &wrong); !errors.As(err, &held) || held.AssignmentID != first.ID || held.MemberID != dave.ID {
		t.Fatalf("stale expectation: %v, want PositionHeldError naming %s/%s", err, first.ID, dave.ID)
	}

	ended, created, err := store.Handover(ctx, "actor", position.ID, erin.ID, &first.ID)
	if err != nil {
		t.Fatalf("handover: %v", err)
	}
	if ended == nil || ended.ID != first.ID || ended.ValidTo == nil || created.MemberID != erin.ID || created.ValidTo != nil {
		t.Fatalf("ended=%+v created=%+v", ended, created)
	}
	holder, err := store.AssignmentOnDate(ctx, position.ID, time.Now().UTC())
	if err != nil || holder.MemberID != erin.ID {
		t.Fatalf("holder today = %+v, %v; want erin", holder, err)
	}
	var tuples int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='position' AND object_id=$1 AND relation='holder' AND subject_id=$2`, position.ID.String(), erin.ID.String()).Scan(&tuples); err != nil || tuples != 1 {
		t.Fatalf("erin's holder tuple = %d, %v; want 1", tuples, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='position' AND object_id=$1 AND relation='holder' AND subject_id=$2`, position.ID.String(), dave.ID.String()).Scan(&tuples); err != nil || tuples != 0 {
		t.Fatalf("dave's holder tuple = %d, %v; want 0", tuples, err)
	}
	var linked int
	if err := admin.QueryRow(ctx, `SELECT count(DISTINCT payload->>'handoverId') FROM audit.org__events WHERE action IN ('org.assignment.end','org.assignment.create') AND payload ? 'handoverId'`).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("distinct handoverId across the two audit events = %d, %v; want 1", linked, err)
	}

	// Idempotent: Erin already holds it.
	ended, again, err := store.Handover(ctx, "actor", position.ID, erin.ID, nil)
	if err != nil || ended != nil || again.ID != created.ID {
		t.Fatalf("repeat handover: ended=%+v again=%+v err=%v; want no change", ended, again, err)
	}
}
