// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mondayAt returns the ISO Monday isoMonday resolves 'daysFromToday' from a fixed reference
// point actually inside every test's default config window (allowedPreviousWeeks=4,
// allowedFutureWeeks=1) — anchored on "now" so this stays correct regardless of when the suite
// runs, same approach every other live test in this codebase uses for date-bound business rules.
func testWeekStart(t *testing.T) time.Time {
	t.Helper()
	return isoMonday(time.Now().UTC())
}

func TestStore_ProjectCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	p, err := store.CreateProject(ctx, "tester", companyID, "ACME", "Acme Rollout", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if p.Status != "active" {
		t.Errorf("status = %q, want active (default)", p.Status)
	}

	if _, err := store.CreateProject(ctx, "tester", companyID, "ACME", "Duplicate", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate code: err = %v, want ErrConflict", err)
	}

	updated, err := store.UpdateProject(ctx, "tester", companyID, p.ID, "ACME", "Acme Rollout v2", "inactive")
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if updated.Status != "inactive" || updated.Name != "Acme Rollout v2" {
		t.Errorf("update did not apply: %+v", updated)
	}

	items, total, err := store.ListProjects(ctx, companyID, 1, 25)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Errorf("total = %d len = %d, want 1/1", total, len(items))
	}
}

func TestStore_UpsertEntry_HoursRulesAndDraftOnly(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID := uuid.New(), uuid.New()
	p, err := store.CreateProject(ctx, "tester", companyID, "PRJ", "Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	day := testWeekStart(t) // Monday, inside the default window

	if _, err := store.UpsertEntry(ctx, "member", companyID, memberID, p.ID, day, 25, 0); !isValidationErr(err, "realHours") {
		t.Errorf("realHours=25: err = %v, want ValidationError(realHours)", err)
	}
	if _, err := store.UpsertEntry(ctx, "member", companyID, memberID, p.ID, day, 4, 5); !isValidationErr(err, "billableHours") {
		t.Errorf("billable>real: err = %v, want ValidationError(billableHours)", err)
	}

	e, err := store.UpsertEntry(ctx, "member", companyID, memberID, p.ID, day, 8, 6)
	if err != nil {
		t.Fatalf("UpsertEntry: %v", err)
	}
	if e.Status != "draft" {
		t.Errorf("status = %q, want draft", e.Status)
	}

	// re-upsert (update) the same entry — allowed while draft.
	e2, err := store.UpsertEntry(ctx, "member", companyID, memberID, p.ID, day, 7, 5)
	if err != nil {
		t.Fatalf("re-upsert while draft: %v", err)
	}
	if e2.ID != e.ID || e2.RealHours != 7 {
		t.Errorf("re-upsert did not update in place: %+v", e2)
	}

	if err := store.DeleteEntry(ctx, "member", companyID, memberID, e.ID); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if err := store.DeleteEntry(ctx, "member", companyID, memberID, e.ID); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("delete again: err = %v, want ErrEntryNotFound", err)
	}
}

func isValidationErr(err error, field string) bool {
	var verr *ValidationError
	return errors.As(err, &verr) && verr.Field == field
}

// TestStore_SubmissionLifecycle proves the full status machine the end-to-end journey needs:
// admin assigns approver -> member enters hours -> submits -> approver rejects w/ reason ->
// member edits+resubmits -> approver approves -> the superseded (rejected) version can never be
// approved.
func TestStore_SubmissionLifecycle(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID, approverMemberID := uuid.New(), uuid.New(), uuid.New()
	memberKcSub, approverKcSub := "kcsub-member-"+memberID.String(), "kcsub-approver-"+approverMemberID.String()

	p, err := store.CreateProject(ctx, "admin", companyID, "PRJ", "Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	week := testWeekStart(t)

	// no approver assigned yet -> submit fails.
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week, 8, 8); err != nil {
		t.Fatalf("UpsertEntry: %v", err)
	}
	if _, _, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, ""); !errors.Is(err, ErrNoApproverAssigned) {
		t.Fatalf("submit before approver assigned: err = %v, want ErrNoApproverAssigned", err)
	}

	// admin assigns approver (RecordApproverAssignment is the store-level half of the
	// approvers API; the HTTP layer additionally grants the authz relations first).
	if _, err := store.RecordApproverAssignment(ctx, "admin", companyID, memberID, approverMemberID, memberKcSub, approverKcSub); err != nil {
		t.Fatalf("RecordApproverAssignment: %v", err)
	}

	// member enters hours (already did above) and submits.
	v1, created, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, "")
	if err != nil {
		t.Fatalf("SubmitWeek v1: %v", err)
	}
	if !created || v1.VersionNumber != 1 || !v1.IsCurrent || v1.Status != "submitted" {
		t.Fatalf("v1 = %+v, want version 1/current/submitted", v1)
	}

	// non-approver cannot approve.
	if _, err := store.ApproveSubmission(ctx, memberKcSub, companyID, v1.ID); !errors.Is(err, ErrNotAssignedApprover) {
		t.Fatalf("approve by non-approver: err = %v, want ErrNotAssignedApprover", err)
	}

	// reject requires a reason.
	if _, err := store.RejectSubmission(ctx, approverKcSub, companyID, v1.ID, ""); !isValidationErr(err, "reason") {
		t.Fatalf("reject without reason: err = %v, want ValidationError(reason)", err)
	}

	// approver rejects with a reason -> entries revert to draft.
	rejected, err := store.RejectSubmission(ctx, approverKcSub, companyID, v1.ID, "wrong project code")
	if err != nil {
		t.Fatalf("RejectSubmission: %v", err)
	}
	if rejected.Status != "rejected" || rejected.RejectReason == nil || *rejected.RejectReason != "wrong project code" {
		t.Fatalf("rejected = %+v", rejected)
	}

	// the rejected version, though still is_current, cannot be approved again once rejected
	// (status != submitted).
	if _, err := store.ApproveSubmission(ctx, approverKcSub, companyID, v1.ID); !errors.Is(err, ErrSubmissionNotSubmitted) {
		t.Fatalf("approve a rejected submission: err = %v, want ErrSubmissionNotSubmitted", err)
	}

	// member edits (entries are draft again) and resubmits -> version 2, supersedes v1.
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week, 8, 7); err != nil {
		t.Fatalf("edit after reject: %v", err)
	}
	v2, created, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, "")
	if err != nil {
		t.Fatalf("SubmitWeek v2: %v", err)
	}
	if !created || v2.VersionNumber != 2 || v2.SupersedesID == nil || *v2.SupersedesID != v1.ID || v2.RootID != v1.RootID {
		t.Fatalf("v2 = %+v, want version 2 supersedes v1 same root", v2)
	}

	// v1 is now superseded -> can never be approved, even though it exists.
	if _, err := store.ApproveSubmission(ctx, approverKcSub, companyID, v1.ID); !errors.Is(err, ErrSubmissionSuperseded) {
		t.Fatalf("approve superseded v1: err = %v, want ErrSubmissionSuperseded", err)
	}

	// approver approves v2 (the current version).
	approved, err := store.ApproveSubmission(ctx, approverKcSub, companyID, v2.ID)
	if err != nil {
		t.Fatalf("ApproveSubmission v2: %v", err)
	}
	if approved.Status != "approved" {
		t.Fatalf("approved = %+v", approved)
	}

	// view=approvals lists it for the approver; view=mine lists it for the member.
	mine, _, err := store.ListSubmissions(ctx, companyID, "mine", memberKcSub, memberID, 1, 25)
	if err != nil || len(mine) == 0 {
		t.Fatalf("ListSubmissions mine: %v items=%d", err, len(mine))
	}
	approvals, _, err := store.ListSubmissions(ctx, companyID, "approvals", approverKcSub, uuid.Nil, 1, 25)
	if err != nil || len(approvals) == 0 {
		t.Fatalf("ListSubmissions approvals: %v items=%d", err, len(approvals))
	}
}

// TestCheckMigrationsApplied_Success covers CheckMigrationsApplied (same convention as every other
// module's own dedicated test for it, e.g. modules/notification/service/store_test.go).
func TestCheckMigrationsApplied_Success(t *testing.T) {
	pool := newTestPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("expected migrations applied, got: %v", err)
	}
}

// TestValidationError_Error covers ValidationError.Error() (every other test that produces a
// *ValidationError only ever type-asserts it, never formats it).
func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "code", Message: "must match ^[A-Z0-9_-]{1,20}$"}
	got := err.Error()
	if !strings.Contains(got, "code") || !strings.Contains(got, "must match") {
		t.Fatalf("Error() = %q, want it to mention the field and message", got)
	}
}

// TestStore_SubmitWeek_IdempotencyKeyReuse covers findSubmissionByIdempotencyKey's found branch
// (every other test calls SubmitWeek with an empty key) and
// SubmitWeek's own idempotent-replay branch: the same key on a second call returns the FIRST
// submission unchanged (created=false), never a second version.
func TestStore_SubmitWeek_IdempotencyKeyReuse(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID, approverMemberID := uuid.New(), uuid.New(), uuid.New()
	memberKcSub, approverKcSub := "kcsub-member-idem", "kcsub-approver-idem"

	p, err := store.CreateProject(ctx, "admin", companyID, "IDEM", "Idem Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	week := testWeekStart(t)
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week, 8, 8); err != nil {
		t.Fatalf("UpsertEntry: %v", err)
	}
	if _, err := store.RecordApproverAssignment(ctx, "admin", companyID, memberID, approverMemberID, memberKcSub, approverKcSub); err != nil {
		t.Fatalf("RecordApproverAssignment: %v", err)
	}

	key := "idem-key-1"
	first, created, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, key)
	if err != nil {
		t.Fatalf("SubmitWeek first: %v", err)
	}
	if !created {
		t.Fatalf("first call: created = false, want true")
	}

	second, created, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week, key)
	if err != nil {
		t.Fatalf("SubmitWeek replay: %v", err)
	}
	if created {
		t.Fatalf("replay call: created = true, want false (idempotent replay)")
	}
	if second.ID != first.ID || second.VersionNumber != first.VersionNumber {
		t.Fatalf("replay = %+v, want the same submission as first = %+v", second, first)
	}
}

// TestStore_SubmitWeek_IdempotencyKeyConflict: the same Idempotency-Key
// reused by the SAME company+member but against a DIFFERENT weekStart must be rejected as
// ErrIdempotencyConflict, never silently replay the first week's submission — idempotency keys
// are payload-bound (409 on conflicting reuse), proven here at the store layer
// (http_more_test.go proves the HTTP 409 IDEMPOTENCY_CONFLICT mapping).
func TestStore_SubmitWeek_IdempotencyKeyConflict(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID, memberID, approverMemberID := uuid.New(), uuid.New(), uuid.New()
	memberKcSub, approverKcSub := "kcsub-member-idemconflict", "kcsub-approver-idemconflict"

	p, err := store.CreateProject(ctx, "admin", companyID, "IDEMC", "Idem Conflict Project", "")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	week1 := testWeekStart(t)
	week2 := week1.AddDate(0, 0, -7) // a different but still-in-window Monday
	if _, err := store.RecordApproverAssignment(ctx, "admin", companyID, memberID, approverMemberID, memberKcSub, approverKcSub); err != nil {
		t.Fatalf("RecordApproverAssignment: %v", err)
	}
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week1, 8, 8); err != nil {
		t.Fatalf("UpsertEntry week1: %v", err)
	}
	if _, err := store.UpsertEntry(ctx, memberKcSub, companyID, memberID, p.ID, week2, 4, 4); err != nil {
		t.Fatalf("UpsertEntry week2: %v", err)
	}

	key := "idem-key-conflict-1"
	if _, created, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week1, key); err != nil {
		t.Fatalf("SubmitWeek week1: %v", err)
	} else if !created {
		t.Fatalf("first call: created = false, want true")
	}

	// same key, different weekStart -> conflict, never a silent replay of week1's submission.
	if _, _, err := store.SubmitWeek(ctx, memberKcSub, companyID, memberID, week2, key); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("SubmitWeek week2 with reused key: err = %v, want ErrIdempotencyConflict", err)
	}
}

func TestStore_Config_DefaultsThenUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	cfg, err := store.GetConfig(ctx, companyID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !cfg.EnforceBillableWithinActual || cfg.AllowBillableAboveEightHours || cfg.AllowedPreviousWeeks != 4 || cfg.AllowedFutureWeeks != 1 {
		t.Errorf("defaults = %+v, want the defaults", cfg)
	}

	updated, err := store.UpdateConfig(ctx, "admin", companyID, Config{
		EnforceBillableWithinActual: false, AllowBillableAboveEightHours: true, AllowedPreviousWeeks: 8, AllowedFutureWeeks: 2,
	})
	if err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	if updated.AllowedPreviousWeeks != 8 || updated.AllowedFutureWeeks != 2 {
		t.Errorf("updated = %+v", updated)
	}

	reread, err := store.GetConfig(ctx, companyID)
	if err != nil {
		t.Fatalf("GetConfig reread: %v", err)
	}
	if reread.AllowedPreviousWeeks != 8 {
		t.Errorf("reread = %+v, want persisted update", reread)
	}
}
