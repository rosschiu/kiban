// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/modulekit"
)

// ---- entries ------------------------------------------------------------------------------------

type entryWire struct {
	ID            string  `json:"id"`
	CompanyID     string  `json:"companyId"`
	MemberID      string  `json:"memberId"`
	ProjectID     string  `json:"projectId"`
	EntryDate     string  `json:"entryDate"`
	RealHours     float64 `json:"realHours"`
	BillableHours float64 `json:"billableHours"`
	Status        string  `json:"status"`
}

func toEntryWire(e Entry) entryWire {
	return entryWire{
		ID: e.ID.String(), CompanyID: e.CompanyID.String(), MemberID: e.MemberID.String(), ProjectID: e.ProjectID.String(),
		EntryDate: e.EntryDate.Format("2006-01-02"), RealHours: e.RealHours, BillableHours: e.BillableHours, Status: e.Status,
	}
}

func (svc *Service) handleListEntries(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	weekStart, ok := parseWeekStart(w, r.URL.Query().Get("weekStart"))
	if !ok {
		return
	}
	memberID, ok := svc.resolveCallerMember(w, r, companyID.String(), rc.Subject)
	if !ok {
		return
	}
	items, err := svc.Store.ListEntriesForWeek(r.Context(), companyID, memberID, weekStart)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]entryWire, len(items))
	for i, it := range items {
		wire[i] = toEntryWire(it)
	}
	errenv.WriteData(w, http.StatusOK, map[string]any{"items": wire})
}

type upsertEntryRequest struct {
	ProjectID     string  `json:"projectId"`
	EntryDate     string  `json:"entryDate"`
	RealHours     float64 `json:"realHours"`
	BillableHours float64 `json:"billableHours"`
}

func (svc *Service) handleUpsertEntry(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req upsertEntryRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	projectID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "projectId must be a valid UUID", Details: map[string]string{"field": "projectId"}})
		return
	}
	entryDate, ok := parseDate(w, req.EntryDate)
	if !ok {
		return
	}
	memberID, ok := svc.resolveCallerMember(w, r, companyID.String(), rc.Subject)
	if !ok {
		return
	}
	e, err := svc.Store.UpsertEntry(r.Context(), rc.Subject, companyID, memberID, projectID, entryDate, req.RealHours, req.BillableHours)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toEntryWire(e))
}

func (svc *Service) handleDeleteEntry(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	entryID, ok := modulekit.ParsePathUUID(w, r, "entryId")
	if !ok {
		return
	}
	memberID, ok := svc.resolveCallerMember(w, r, companyID.String(), rc.Subject)
	if !ok {
		return
	}
	if err := svc.Store.DeleteEntry(r.Context(), rc.Subject, companyID, memberID, entryID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseDate(w http.ResponseWriter, raw string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "entryDate must be YYYY-MM-DD", Details: map[string]string{"field": "entryDate"}})
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

// ---- submissions --------------------------------------------------------------------------------

type submissionWire struct {
	ID                       string  `json:"id"`
	CompanyID                string  `json:"companyId"`
	MemberID                 string  `json:"memberId"`
	WeekStart                string  `json:"weekStart"`
	VersionNumber            int     `json:"versionNumber"`
	RootID                   string  `json:"rootId"`
	SupersedesID             *string `json:"supersedesId"`
	IsCurrent                bool    `json:"isCurrent"`
	Status                   string  `json:"status"`
	AssignedApproverMemberID string  `json:"assignedApproverMemberId"`
	RejectReason             *string `json:"rejectReason"`
	Permissions              struct {
		CanApprove bool `json:"canApprove"`
		CanReject  bool `json:"canReject"`
		CanRevert  bool `json:"canRevert"`
	} `json:"permissions"`
}

// toSubmissionWire embeds the per-row `permissions` object PERF-001 requires — computed here from
// data already on hand (assigned approver + current caller + status/isCurrent), never a second
// per-row authz call (the page-level featureKey check already authorized the PAGE; this is a
// pure data-shape function of who is looking and what state the row is in).
func toSubmissionWire(s Submission, callerKcSub string, callerIsAssignedApprover bool) submissionWire {
	w := submissionWire{
		ID: s.ID.String(), CompanyID: s.CompanyID.String(), MemberID: s.MemberID.String(),
		WeekStart: s.WeekStart.Format("2006-01-02"), VersionNumber: s.VersionNumber, RootID: s.RootID.String(),
		IsCurrent: s.IsCurrent, Status: s.Status, AssignedApproverMemberID: s.AssignedApproverMemberID.String(),
		RejectReason: s.RejectReason,
	}
	if s.SupersedesID != nil {
		id := s.SupersedesID.String()
		w.SupersedesID = &id
	}
	canDecide := callerIsAssignedApprover && s.IsCurrent && s.Status == "submitted"
	w.Permissions.CanApprove = canDecide
	w.Permissions.CanReject = canDecide
	w.Permissions.CanRevert = false
	return w
}

func (svc *Service) handleSubmitWeek(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req struct {
		WeekStart string `json:"weekStart"`
	}
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	weekStart, ok := parseWeekStart(w, req.WeekStart)
	if !ok {
		return
	}
	memberID, ok := svc.resolveCallerMember(w, r, companyID.String(), rc.Subject)
	if !ok {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}
	sub, created, err := svc.Store.SubmitWeek(r.Context(), rc.Subject, companyID, memberID, weekStart, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	errenv.WriteData(w, status, toSubmissionWire(sub, rc.Subject, sub.AssignedApproverKcSub == rc.Subject))
}

func (svc *Service) handleGetSubmission(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	submissionID, ok := modulekit.ParsePathUUID(w, r, "submissionId")
	if !ok {
		return
	}
	sub, err := svc.Store.GetSubmission(r.Context(), companyID, submissionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toSubmissionWire(sub, rc.Subject, sub.AssignedApproverKcSub == rc.Subject))
}

func (svc *Service) handleApproveSubmission(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	submissionID, ok := modulekit.ParsePathUUID(w, r, "submissionId")
	if !ok {
		return
	}
	sub, err := svc.Store.ApproveSubmission(r.Context(), rc.Subject, companyID, submissionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toSubmissionWire(sub, rc.Subject, true))
}

func (svc *Service) handleRejectSubmission(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	submissionID, ok := modulekit.ParsePathUUID(w, r, "submissionId")
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	sub, err := svc.Store.RejectSubmission(r.Context(), rc.Subject, companyID, submissionID, req.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toSubmissionWire(sub, rc.Subject, true))
}

func (svc *Service) handleListSubmissions(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "mine"
	}
	memberID, ok := svc.resolveCallerMember(w, r, companyID.String(), rc.Subject)
	if !ok {
		return
	}
	page, pageSize := modulekit.PageParams(r)
	items, total, err := svc.Store.ListSubmissions(r.Context(), companyID, view, rc.Subject, memberID, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, items, total, page, pageSize, func(it Submission) submissionWire {
		return toSubmissionWire(it, rc.Subject, it.AssignedApproverKcSub == rc.Subject)
	})
}
