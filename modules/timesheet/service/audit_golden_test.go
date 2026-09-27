// SPDX-License-Identifier: Apache-2.0

// Golden tests for timesheet's key audit event PAYLOAD SHAPES (keys + JSON value types, never
// values — see internal/testauditgolden's doc comment). Covers timesheet.submission.submit,
// timesheet.submission.approve, timesheet.submission.reject and timesheet.approver.assign. Each test
// drives the REAL store method against the live test DB (same fixture pattern as
// TestStore_SubmissionLifecycle in store_live_test.go), then reads the actual persisted payload back
// out of audit.timesheet__events.
package timesheet

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testauditgolden"
)

func fetchAuditPayload(t *testing.T, store *Store, subject, action string) []byte {
	t.Helper()
	var payload []byte
	err := store.pool.QueryRow(context.Background(), `
		SELECT payload FROM audit.timesheet__events
		WHERE subject = $1 AND action = $2
		ORDER BY occurred_at DESC LIMIT 1`, subject, action).Scan(&payload)
	if err != nil {
		t.Fatalf("fetch audit payload for subject=%s action=%s: %v", subject, action, err)
	}
	return payload
}

func assertGoldenShape(t *testing.T, name string, payload []byte) {
	t.Helper()
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_"+name+".txt"), shape)
}

func TestAuditGolden_ApproverAssign(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID, approverMemberID := uuid.New(), uuid.New(), uuid.New()
	memberKcSub, approverKcSub := "kcsub-member-"+memberID.String(), "kcsub-approver-"+approverMemberID.String()
	if _, err := store.RecordApproverAssignment(ctx, "admin", companyID, memberID, approverMemberID, memberKcSub, approverKcSub); err != nil {
		t.Fatalf("RecordApproverAssignment: %v", err)
	}
	payload := fetchAuditPayload(t, store, "company_module:"+companyID.String()+"/timesheet", "timesheet.approver.assign")
	assertGoldenShape(t, "approver_assign", payload)
}

func TestAuditGolden_SubmitApproveReject(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID, approverMemberID := uuid.New(), uuid.New(), uuid.New()
	memberKcSub, approverKcSub := "kcsub-member-"+memberID.String(), "kcsub-approver-"+approverMemberID.String()

	p, err := store.CreateProject(ctx, "admin", companyID, "PRJ", "Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	week := testWeekStart(t)
	if _, err := store.RecordApproverAssignment(ctx, "admin", companyID, memberID, approverMemberID, memberKcSub, approverKcSub); err != nil {
		t.Fatalf("RecordApproverAssignment: %v", err)
	}
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week, 8, 8); err != nil {
		t.Fatalf("UpsertEntry: %v", err)
	}

	v1, _, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, "")
	if err != nil {
		t.Fatalf("SubmitWeek: %v", err)
	}
	submitPayload := fetchAuditPayload(t, store, "submission:"+v1.ID.String(), "timesheet.submission.submit")
	assertGoldenShape(t, "submission_submit", submitPayload)

	if _, err := store.RejectSubmission(ctx, approverKcSub, companyID, v1.ID, "needs correction"); err != nil {
		t.Fatalf("RejectSubmission: %v", err)
	}
	rejectPayload := fetchAuditPayload(t, store, "submission:"+v1.ID.String(), "timesheet.submission.reject")
	assertGoldenShape(t, "submission_reject", rejectPayload)

	// re-enter hours (rejection put entries back to draft) and resubmit for the approve path.
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week, 8, 8); err != nil {
		t.Fatalf("UpsertEntry v2: %v", err)
	}
	v2, _, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, "")
	if err != nil {
		t.Fatalf("SubmitWeek v2: %v", err)
	}
	if _, err := store.ApproveSubmission(ctx, approverKcSub, companyID, v2.ID); err != nil {
		t.Fatalf("ApproveSubmission: %v", err)
	}
	approvePayload := fetchAuditPayload(t, store, "submission:"+v2.ID.String(), "timesheet.submission.approve")
	assertGoldenShape(t, "submission_approve", approvePayload)
}
