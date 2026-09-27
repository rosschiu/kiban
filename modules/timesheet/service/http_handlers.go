// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/modulekit"
)

// ---- config -----------------------------------------------------------------------------------

type configWire struct {
	CompanyID                    string `json:"companyId"`
	EnforceBillableWithinActual  bool   `json:"enforceBillableWithinActual"`
	AllowBillableAboveEightHours bool   `json:"allowBillableAboveEightHours"`
	AllowedPreviousWeeks         int    `json:"allowedPreviousWeeks"`
	AllowedFutureWeeks           int    `json:"allowedFutureWeeks"`
}

func toConfigWire(c Config) configWire {
	return configWire{
		CompanyID: c.CompanyID.String(), EnforceBillableWithinActual: c.EnforceBillableWithinActual,
		AllowBillableAboveEightHours: c.AllowBillableAboveEightHours,
		AllowedPreviousWeeks:         c.AllowedPreviousWeeks, AllowedFutureWeeks: c.AllowedFutureWeeks,
	}
}

func (svc *Service) handleGetConfig(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	c, err := svc.Store.GetConfig(r.Context(), companyID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toConfigWire(c))
}

type updateConfigRequest struct {
	EnforceBillableWithinActual  bool `json:"enforceBillableWithinActual"`
	AllowBillableAboveEightHours bool `json:"allowBillableAboveEightHours"`
	AllowedPreviousWeeks         int  `json:"allowedPreviousWeeks"`
	AllowedFutureWeeks           int  `json:"allowedFutureWeeks"`
}

func (svc *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req updateConfigRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	c, err := svc.Store.UpdateConfig(r.Context(), rc.Subject, companyID, Config{
		EnforceBillableWithinActual: req.EnforceBillableWithinActual, AllowBillableAboveEightHours: req.AllowBillableAboveEightHours,
		AllowedPreviousWeeks: req.AllowedPreviousWeeks, AllowedFutureWeeks: req.AllowedFutureWeeks,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toConfigWire(c))
}

// ---- projects ----------------------------------------------------------------------------------

type projectWire struct {
	ID        string `json:"id"`
	CompanyID string `json:"companyId"`
	Code      string `json:"code"`
	Name      string `json:"name"`
	Status    string `json:"status"`
}

func toProjectWire(p Project) projectWire {
	return projectWire{ID: p.ID.String(), CompanyID: p.CompanyID.String(), Code: p.Code, Name: p.Name, Status: p.Status}
}

type createProjectRequest struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func (svc *Service) handleCreateProject(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req createProjectRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	p, err := svc.Store.CreateProject(r.Context(), rc.Subject, companyID, req.Code, req.Name, req.Status)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, toProjectWire(p))
}

func (svc *Service) handleUpdateProject(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	projectID, ok := modulekit.ParsePathUUID(w, r, "projectId")
	if !ok {
		return
	}
	var req createProjectRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	p, err := svc.Store.UpdateProject(r.Context(), rc.Subject, companyID, projectID, req.Code, req.Name, req.Status)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toProjectWire(p))
}

func (svc *Service) handleListProjects(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	page, pageSize := modulekit.PageParams(r)
	items, total, err := svc.Store.ListProjects(r.Context(), companyID, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, items, total, page, pageSize, toProjectWire)
}

// ---- approvers ---------------------------------------------------------------------------------

type approverAssignmentWire struct {
	CompanyID        string `json:"companyId"`
	MemberID         string `json:"memberId"`
	ApproverMemberID string `json:"approverMemberId"`
	AssignedAt       string `json:"assignedAt"`
}

func toApproverAssignmentWire(a ApproverAssignment) approverAssignmentWire {
	return approverAssignmentWire{
		CompanyID: a.CompanyID.String(), MemberID: a.MemberID.String(), ApproverMemberID: a.ApproverMemberID.String(),
		AssignedAt: a.AssignedAt.Format(rfc3339),
	}
}

const rfc3339 = "2006-01-02T15:04:05.999999999Z07:00"

type assignApproverRequest struct {
	MemberID         string `json:"memberId"`
	ApproverMemberID string `json:"approverMemberId"`
}

// handleAssignApprover is the approvers API: it wraps the EXISTING authz
// grants surface (never a parallel grant store) — grants company_module
// #submitter to memberId's kcSub and #approver to approverMemberId's kcSub, THEN records the
// read-side index row (store_approvers.go's header comment explains why the index exists).
func (svc *Service) handleAssignApprover(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req assignApproverRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	memberID, err := uuid.Parse(req.MemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "memberId must be a valid UUID", Details: map[string]string{"field": "memberId"}})
		return
	}
	approverMemberID, err := uuid.Parse(req.ApproverMemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "approverMemberId must be a valid UUID", Details: map[string]string{"field": "approverMemberId"}})
		return
	}

	member, err := svc.Org.GetMember(r.Context(), memberID.String())
	if err != nil || member.KcSub == "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "memberId has no linked user to grant submitter access to", Details: map[string]string{"field": "memberId"}})
		return
	}
	approverMember, err := svc.Org.GetMember(r.Context(), approverMemberID.String())
	if err != nil || approverMember.KcSub == "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "approverMemberId has no linked user to grant approver access to", Details: map[string]string{"field": "approverMemberId"}})
		return
	}

	correlationID := r.Header.Get("x-correlation-id")
	if err := svc.Authz.GrantRelation(r.Context(), rc.RawBearer, companyID.String(), "submitter", member.KcSub, correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant submitter relation"})
		return
	}
	if err := svc.Authz.GrantRelation(r.Context(), rc.RawBearer, companyID.String(), "approver", approverMember.KcSub, correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant approver relation"})
		return
	}

	a, err := svc.Store.RecordApproverAssignment(r.Context(), rc.Subject, companyID, memberID, approverMemberID, member.KcSub, approverMember.KcSub)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toApproverAssignmentWire(a))
}

func (svc *Service) handleListApprovers(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	page, pageSize := modulekit.PageParams(r)
	items, total, err := svc.Store.ListApproverAssignments(r.Context(), companyID, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, items, total, page, pageSize, toApproverAssignmentWire)
}
