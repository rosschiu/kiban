// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Closes the gap TestHTTP_FullJourney leaves behind — that journey only exercises
// create-project/assign-approver/upsert-entry/submit/reject/resubmit/approve; the
// list/get/update/delete handlers, config handlers, and a batch of writeStoreError/decodeJSON/
// parsePathUUID/parseWeekStart/resolveCallerMember branches are covered here. Every test below
// asserts response status AND at least one field of the decoded body (never a bare status-code
// check).

type errEnvelope struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) errEnvelope {
	t.Helper()
	var e errEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, rec.Body.String())
	}
	return e
}

func TestHTTP_Ready_DBReachable(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/ready", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Data.Status != "ok" {
		t.Fatalf("status = %q, want ok", body.Data.Status)
	}
}

// TestHTTP_Config_GetDefaultsThenUpdate covers handleGetConfig/handleUpdateConfig's happy paths
// and toConfigWire.
func TestHTTP_Config_GetDefaultsThenUpdate(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"
	f := newHTTPFixture(t, nil, map[string]bool{adminSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get config: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Data configWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if !got.Data.EnforceBillableWithinActual || got.Data.AllowedPreviousWeeks != 4 {
		t.Fatalf("defaults = %+v", got.Data)
	}

	rec = f.do(t, http.MethodPut, "/api/timesheet/v1/companies/"+companyID+"/config", tok,
		`{"enforceBillableWithinActual":false,"allowBillableAboveEightHours":true,"allowedPreviousWeeks":8,"allowedFutureWeeks":2}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update config: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data.AllowedPreviousWeeks != 8 || got.Data.EnforceBillableWithinActual {
		t.Fatalf("updated = %+v", got.Data)
	}
}

// TestHTTP_Config_Update_ValidationError covers writeStoreError's *ValidationError branch via the
// HTTP layer (store-level ValidationError paths for config are already proven directly in
// store_live_test.go — this proves the handler wires the 422 envelope through correctly).
func TestHTTP_Config_Update_ValidationError(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"
	f := newHTTPFixture(t, nil, map[string]bool{adminSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPut, "/api/timesheet/v1/companies/"+companyID+"/config", tok,
		`{"allowedPreviousWeeks":-1,"allowedFutureWeeks":0}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "VALIDATION_ERROR" || e.Error.Details["field"] != "allowedPreviousWeeks" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Projects_ListUpdate_NotFoundAndConflict covers handleListProjects (0%),
// handleUpdateProject's happy/404/conflict branches, and ListProjects pagination end to end.
func TestHTTP_Projects_ListUpdate_NotFoundAndConflict(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"
	f := newHTTPFixture(t, nil, map[string]bool{adminSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", tok, `{"code":"P1","name":"One"}`, nil)
	var p1 struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p1)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create P1: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", tok, `{"code":"P2","name":"Two"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create P2: %d %s", rec.Code, rec.Body.String())
	}

	// list.
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/projects?page=1&pageSize=10", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list projects: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Data struct {
			Items []projectWire `json:"items"`
			Total int           `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 2 || len(page.Data.Items) != 2 {
		t.Fatalf("page = %+v", page.Data)
	}

	// update happy path.
	rec = f.do(t, http.MethodPut, "/api/timesheet/v1/companies/"+companyID+"/projects/"+p1.Data.ID, tok, `{"code":"P1","name":"One Renamed","status":"inactive"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update project: %d %s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Data.Name != "One Renamed" || updated.Data.Status != "inactive" {
		t.Fatalf("updated = %+v", updated.Data)
	}

	// update unknown project id -> 404 (ErrProjectNotFound via pgx.ErrNoRows).
	rec = f.do(t, http.MethodPut, "/api/timesheet/v1/companies/"+companyID+"/projects/"+uuid.New().String(), tok, `{"code":"PX","name":"Ghost"}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update unknown project: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	// update P1's code to collide with P2's code -> 409 conflict.
	rec = f.do(t, http.MethodPut, "/api/timesheet/v1/companies/"+companyID+"/projects/"+p1.Data.ID, tok, `{"code":"P2","name":"Collide"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("colliding update: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "CONFLICT" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Projects_Create_ValidationError covers handleCreateProject's validation branch via
// bad project code shape.
func TestHTTP_Projects_Create_ValidationError(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"
	f := newHTTPFixture(t, nil, map[string]bool{adminSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", tok, `{"code":"bad code!","name":"X"}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "code" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Approvers_List covers handleListApprovers.
func TestHTTP_Approvers_List(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"

	members := map[string]fakeMember{
		memberID:   {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID: {CompanyID: companyID, KcSub: approverSub, IsActive: true},
	}
	companyMembers := map[string]bool{adminSub: true, memberSub: true, approverSub: true}
	f := newHTTPFixture(t, members, companyMembers, map[string]bool{adminSub: true})
	adminTok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		strings.NewReplacer("MID", memberID, "AID", approverID).Replace(`{"memberId":"MID","approverMemberId":"AID"}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list approvers: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Data struct {
			Items []approverAssignmentWire `json:"items"`
			Total int                      `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 1 || len(page.Data.Items) != 1 || page.Data.Items[0].MemberID != memberID {
		t.Fatalf("page = %+v", page.Data)
	}
}

// TestHTTP_AssignApprover_BadInput covers handleAssignApprover's UUID-parse (400) and
// org-member-has-no-linked-user (422) branches — none exercised by TestHTTP_FullJourney, which
// only ever hits the all-valid path.
func TestHTTP_AssignApprover_BadInput(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"
	f := newHTTPFixture(t, nil, map[string]bool{adminSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", tok, `{"memberId":"not-a-uuid","approverMemberId":"also-not-a-uuid"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad memberId: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "memberId" {
		t.Fatalf("error = %+v", e.Error)
	}

	validButUnknown := uuid.New().String()
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", tok,
		`{"memberId":"`+validButUnknown+`","approverMemberId":"also-not-a-uuid"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad approverMemberId: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "approverMemberId" {
		t.Fatalf("error = %+v", e.Error)
	}

	// memberId resolves to nothing in org (fake org 404s any id not in its members map) -> 422
	// "no linked user to grant submitter access to".
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", tok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown memberId: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "memberId" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_AssignApprover_ApproverHasNoLinkedUser covers the SECOND org.GetMember branch (the
// approverMemberId lookup) distinctly from the memberId one above.
func TestHTTP_AssignApprover_ApproverHasNoLinkedUser(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	adminSub, memberSub := "kcsub-admin", "kcsub-member"
	members := map[string]fakeMember{memberID: {CompanyID: companyID, KcSub: memberSub, IsActive: true}}
	f := newHTTPFixture(t, members, map[string]bool{adminSub: true, memberSub: true}, map[string]bool{adminSub: true})
	tok := f.token(t, adminSub)

	approverID := uuid.New().String() // not in members map -> org 404s it
	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", tok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "approverMemberId" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_AssignApprover_AuthzGrantUnavailable_503 proves the fail-closed path when authz's
// grants endpoint is down mid-assignment — this module must never fall back to recording the
// read-side index row without the real grant having succeeded.
func TestHTTP_AssignApprover_AuthzGrantUnavailable_503(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"
	members := map[string]fakeMember{
		memberID:   {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID: {CompanyID: companyID, KcSub: approverSub, IsActive: true},
	}

	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	orgSrv := newFakeOrg(t, members)
	// authz's /can still allows (so withAuth passes), but /grants is unreachable — a down authz
	// dependency mid-write, not a down authz-decision dependency.
	downAuthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/authz/effective-access/can":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(downAuthz.Close)

	authzClient := NewAuthzClient(&http.Client{Timeout: 2 * time.Second}, downAuthz.URL)
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, orgSrv.URL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient)
	f := &httpFixture{handler: svc.Routes(), issuer: issuer}
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", tok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Authz_Unavailable_503 proves withAuth's own authz-down branch (Can returning err) —
// distinct from AssignApprover's grants-down branch above. authz-down must never allow.
func TestHTTP_Authz_Unavailable_503(t *testing.T) {
	companyID := uuid.New().String()
	adminSub := "kcsub-admin"

	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	downAuthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(downAuthz.Close)

	authzClient := NewAuthzClient(&http.Client{Timeout: 2 * time.Second}, downAuthz.URL)
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1")
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient)
	f := &httpFixture{handler: svc.Routes(), issuer: issuer}
	tok := f.token(t, adminSub)

	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", tok, "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_ResolveCallerMember_OrgUnavailable_503 covers resolveCallerMember's org-error branch
// (distinct from its not-a-member 422 branch, already proven at TestHTTP_NonMember_403's authz
// layer) — org itself unreachable while authz still allows.
func TestHTTP_ResolveCallerMember_OrgUnavailable_503(t *testing.T) {
	companyID := uuid.New().String()
	memberSub := "kcsub-member"

	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	authzSrv := newFakeAuthz(t, map[string]bool{memberSub: true}, nil)
	authzClient := NewAuthzClient(&http.Client{Timeout: 2 * time.Second}, authzSrv.URL)
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1")
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient)
	f := &httpFixture{handler: svc.Routes(), issuer: issuer}
	tok := f.token(t, memberSub)

	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart=2026-08-10", tok, "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "INTERNAL_ERROR" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_ResolveCallerMember_NotActiveMember_422 covers the "no active member mapping" branch
// — a caller authz allows (company member) but org reports them not-a-member/not-active.
func TestHTTP_ResolveCallerMember_NotActiveMember_422(t *testing.T) {
	companyID := uuid.New().String()
	memberSub := "kcsub-member"
	f := newHTTPFixture(t, nil /* no org members recorded */, map[string]bool{memberSub: true}, nil)
	tok := f.token(t, memberSub)

	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart=2026-08-10", tok, "", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "memberId" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Entries_ListAndDelete_ViaAdminSeededProject seeds the project as an admin caller, then
// exercises list/delete as the member — avoids the two-role complexity of the skipped variant
// above while still hitting handleListEntries/handleDeleteEntry for real.
func TestHTTP_Entries_ListAndDelete_ViaAdminSeededProject(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	adminSub, memberSub := "kcsub-admin", "kcsub-member"
	members := map[string]fakeMember{memberID: {CompanyID: companyID, KcSub: memberSub, IsActive: true}}
	f := newHTTPFixture(t, members, map[string]bool{adminSub: true, memberSub: true}, map[string]bool{adminSub: true})
	adminTok := f.token(t, adminSub)
	memberTok := f.token(t, memberSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", adminTok, `{"code":"P1","name":"One"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", rec.Code, rec.Body.String())
	}
	var proj struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &proj)

	week := isoMonday(time.Now().UTC()).Format("2006-01-02")
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
		`{"projectId":"`+proj.Data.ID+`","entryDate":"`+week+`","realHours":8,"billableHours":6}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert entry: %d %s", rec.Code, rec.Body.String())
	}
	var entry struct {
		Data entryWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &entry)

	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart="+week, memberTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list entries: %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Data struct {
			Items []entryWire `json:"items"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Data.Items) != 1 || list.Data.Items[0].ID != entry.Data.ID {
		t.Fatalf("list = %+v", list.Data)
	}

	rec = f.do(t, http.MethodDelete, "/api/timesheet/v1/companies/"+companyID+"/entries/"+entry.Data.ID, memberTok, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete entry: %d %s", rec.Code, rec.Body.String())
	}

	// delete again -> 404 (ErrEntryNotFound).
	rec = f.do(t, http.MethodDelete, "/api/timesheet/v1/companies/"+companyID+"/entries/"+entry.Data.ID, memberTok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete again: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	// invalid entryId UUID -> 400 (parsePathUUID's error branch, distinct from companyId's).
	rec = f.do(t, http.MethodDelete, "/api/timesheet/v1/companies/"+companyID+"/entries/not-a-uuid", memberTok, "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid entryId: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_UpsertEntry_BadInput covers handleUpsertEntry's projectId-not-UUID (400) and
// entryDate-malformed (400) branches, plus decodeJSON's invalid-JSON branch.
func TestHTTP_UpsertEntry_BadInput(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	memberSub := "kcsub-member"
	members := map[string]fakeMember{memberID: {CompanyID: companyID, KcSub: memberSub, IsActive: true}}
	f := newHTTPFixture(t, members, map[string]bool{memberSub: true}, nil)
	tok := f.token(t, memberSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", tok, `not json at all`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON body: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "BAD_REQUEST" {
		t.Fatalf("error = %+v", e.Error)
	}

	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", tok, `{"projectId":"nope","entryDate":"2026-08-10","realHours":1,"billableHours":1}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad projectId: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "projectId" {
		t.Fatalf("error = %+v", e.Error)
	}

	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", tok, `{"projectId":"`+uuid.New().String()+`","entryDate":"not-a-date","realHours":1,"billableHours":1}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad entryDate: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "entryDate" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_ParseWeekStart_Branches covers parseWeekStart's malformed-format (400) and
// non-Monday (422) branches via handleListEntries.
func TestHTTP_ParseWeekStart_Branches(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	memberSub := "kcsub-member"
	members := map[string]fakeMember{memberID: {CompanyID: companyID, KcSub: memberSub, IsActive: true}}
	f := newHTTPFixture(t, members, map[string]bool{memberSub: true}, nil)
	tok := f.token(t, memberSub)

	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart=not-a-date", tok, "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed weekStart: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart=2026-08-11", tok, "", nil) // a Tuesday
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-Monday weekStart: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "weekStart" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_Submissions_ListScopesAndGet covers handleListSubmissions (0%, all three scope values)
// and handleGetSubmission's happy path + 404.
func TestHTTP_Submissions_ListScopesAndGet(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminMemberID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"
	members := map[string]fakeMember{
		memberID:      {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID:    {CompanyID: companyID, KcSub: approverSub, IsActive: true},
		adminMemberID: {CompanyID: companyID, KcSub: adminSub, IsActive: true}, // handleListSubmissions calls resolveCallerMember for every scope, including "all"
	}
	companyMembers := map[string]bool{adminSub: true, memberSub: true, approverSub: true}
	f := newHTTPFixture(t, members, companyMembers, map[string]bool{adminSub: true})
	adminTok, memberTok, approverTok := f.token(t, adminSub), f.token(t, memberSub), f.token(t, approverSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", adminTok, `{"code":"P1","name":"One"}`, nil)
	var proj struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &proj)
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}

	week := isoMonday(time.Now().UTC()).Format("2006-01-02")
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
		`{"projectId":"`+proj.Data.ID+`","entryDate":"`+week+`","realHours":8,"billableHours":6}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert entry: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		Data submissionWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	// view=mine (member's own default).
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list mine: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Data struct {
			Items []submissionWire `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 1 {
		t.Fatalf("view=mine total = %d, want 1", page.Data.Total)
	}

	// view=approvals (approver's queue) — approver's own permissions flags should show
	// canApprove/canReject true for the current submitted row.
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/submissions?view=approvals", approverTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list approvals: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 1 || !page.Data.Items[0].Permissions.CanApprove {
		t.Fatalf("view=approvals = %+v", page.Data)
	}

	// view=all (admin oversight).
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/submissions?view=all", adminTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list all: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 1 {
		t.Fatalf("view=all total = %d, want 1", page.Data.Total)
	}

	// GetSubmission happy path.
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+sub.Data.ID, memberTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get submission: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Data submissionWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data.ID != sub.Data.ID {
		t.Fatalf("get submission id = %q, want %q", got.Data.ID, sub.Data.ID)
	}

	// GetSubmission unknown id -> 404.
	rec = f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+uuid.New().String(), memberTok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get unknown submission: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_SubmitWeek_NoDraftEntries_422 covers writeStoreError's ErrNoDraftEntries branch and
// handleSubmitWeek's Idempotency-Key-too-long (400) branch.
func TestHTTP_SubmitWeek_NoDraftEntries_422(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"
	members := map[string]fakeMember{
		memberID:   {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID: {CompanyID: companyID, KcSub: approverSub, IsActive: true},
	}
	f := newHTTPFixture(t, members, map[string]bool{adminSub: true, memberSub: true, approverSub: true}, map[string]bool{adminSub: true})
	adminTok, memberTok := f.token(t, adminSub), f.token(t, memberSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}

	week := isoMonday(time.Now().UTC()).Format("2006-01-02")
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week+`"}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no draft entries: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "weekStart" {
		t.Fatalf("error = %+v", e.Error)
	}

	longKey := strings.Repeat("k", 201)
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week+`"}`, map[string]string{"Idempotency-Key": longKey})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized idempotency key: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_SubmitWeek_IdempotencyKeyConflict_409 proves writeStoreError's
// ErrIdempotencyConflict branch through the full HTTP round trip — reusing the same
// Idempotency-Key for a submission with a DIFFERENT weekStart is rejected 409
// IDEMPOTENCY_CONFLICT, never a silent replay of the first week's submission (store-level
// proof: TestStore_SubmitWeek_IdempotencyKeyConflict in store_live_test.go).
func TestHTTP_SubmitWeek_IdempotencyKeyConflict_409(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"
	members := map[string]fakeMember{
		memberID:   {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID: {CompanyID: companyID, KcSub: approverSub, IsActive: true},
	}
	f := newHTTPFixture(t, members, map[string]bool{adminSub: true, memberSub: true, approverSub: true}, map[string]bool{adminSub: true})
	adminTok, memberTok := f.token(t, adminSub), f.token(t, memberSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", adminTok, `{"code":"IDEMP","name":"Idem"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", rec.Code, rec.Body.String())
	}
	var proj struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &proj)

	week1 := isoMonday(time.Now().UTC()).Format("2006-01-02")
	week2 := isoMonday(time.Now().UTC()).AddDate(0, 0, -7).Format("2006-01-02")
	for _, wk := range []string{week1, week2} {
		rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
			`{"projectId":"`+proj.Data.ID+`","entryDate":"`+wk+`","realHours":4,"billableHours":4}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("upsert entry %s: %d %s", wk, rec.Code, rec.Body.String())
		}
	}

	key := map[string]string{"Idempotency-Key": "http-idem-conflict-1"}
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week1+`"}`, key)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit week1: %d %s", rec.Code, rec.Body.String())
	}

	// same key, different weekStart -> 409 IDEMPOTENCY_CONFLICT.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week2+`"}`, key)
	if rec.Code != http.StatusConflict {
		t.Fatalf("submit week2 with reused key: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error code = %q, want IDEMPOTENCY_CONFLICT", e.Error.Code)
	}
}

// TestHTTP_RejectSubmission_MissingReason_422 covers decideSubmission's ValidationError(reason)
// branch through the HTTP layer (store-level already proven in store_live_test.go; this proves
// the handler's own decodeJSON + writeStoreError wiring for it).
func TestHTTP_RejectSubmission_MissingReason_422(t *testing.T) {
	companyID := uuid.New().String()
	memberID := uuid.New().String()
	approverID := uuid.New().String()
	adminSub, memberSub, approverSub := "kcsub-admin", "kcsub-member", "kcsub-approver"
	members := map[string]fakeMember{
		memberID:   {CompanyID: companyID, KcSub: memberSub, IsActive: true},
		approverID: {CompanyID: companyID, KcSub: approverSub, IsActive: true},
	}
	f := newHTTPFixture(t, members, map[string]bool{adminSub: true, memberSub: true, approverSub: true}, map[string]bool{adminSub: true})
	adminTok, memberTok, approverTok := f.token(t, adminSub), f.token(t, memberSub), f.token(t, approverSub)

	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", adminTok, `{"code":"P1","name":"One"}`, nil)
	var proj struct {
		Data projectWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &proj)
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		`{"memberId":"`+memberID+`","approverMemberId":"`+approverID+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}
	week := isoMonday(time.Now().UTC()).Format("2006-01-02")
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
		`{"projectId":"`+proj.Data.ID+`","entryDate":"`+week+`","realHours":8,"billableHours":6}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert entry: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok, `{"weekStart":"`+week+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		Data submissionWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+sub.Data.ID+"/reject", approverTok, `{"reason":""}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reject without reason: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Details["field"] != "reason" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_MissingBearer_WWWAuthenticateHeader proves withAuth's 401 branch sets the
// WWW-Authenticate response header (never asserted by TestHTTP_MissingBearer_401).
func TestHTTP_MissingBearer_WWWAuthenticateHeader(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	companyID := uuid.New().String()
	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", "", "", nil)
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}
}
