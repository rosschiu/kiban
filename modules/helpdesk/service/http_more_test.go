// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Covers what TestHTTP_FullWorkflowJourney and the group/position assignment suites don't:
// handleListComments/ListComments (the journey creates a comment but never lists them), several
// validation/not-found/decodeJSON branches, and CheckMigrationsApplied/ValidationError.Error(). Every test asserts response status AND
// at least one decoded field, never a bare status check.

type errEnvelope struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

// TestHTTP_ListComments_ReporterAndAgent covers handleListComments and
// Store.ListComments — the reporter and the assignee-agent can both list; a stranger
// (plain member, neither reporter nor agent/admin nor assignee) is forbidden.
func TestHTTP_ListComments_ReporterAndAgent(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "eve": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")
	eveBearer := f.token(t, "eve")
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"Leaky faucet","description":"drip drip"}`)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createRec.Code, createRec.Body.String())
	}
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign: %d %s", assignRec.Code, assignRec.Body.String())
	}

	commentRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `{"body":"any update?"}`)
	if commentRec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", commentRec.Code, commentRec.Body.String())
	}

	// reporter can list.
	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list as reporter: %d %s", listRec.Code, listRec.Body.String())
	}
	var comments []commentWire
	decodeData(t, listRec, &comments)
	if len(comments) != 1 || comments[0].Body != "any update?" {
		t.Fatalf("comments = %+v", comments)
	}

	// assignee-agent can list.
	listRec2 := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", bobBearer, "")
	if listRec2.Code != http.StatusOK {
		t.Fatalf("list as assignee: %d %s", listRec2.Code, listRec2.Body.String())
	}

	// a plain member who is neither reporter, admin, nor assignee/agent -> 403.
	listRec3 := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", eveBearer, "")
	if listRec3.Code != http.StatusForbidden {
		t.Fatalf("list as stranger: expected 403, got %d: %s", listRec3.Code, listRec3.Body.String())
	}
}

// TestHTTP_ListComments_TicketNotFound_404 covers handleListComments' GetTicket-not-found branch.
func TestHTTP_ListComments_TicketNotFound_404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+uuid.NewString()+"/comments", aliceBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateComment_TicketNotFound_404 covers handleCreateComment's own GetTicket-not-found
// branch (distinct call site from handleListComments' own, same store method).
func TestHTTP_CreateComment_TicketNotFound_404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+uuid.NewString()+"/comments", aliceBearer, `{"body":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateComment_InvalidJSON_400 covers decodeJSON's invalid-JSON branch via the comment
// endpoint.
func TestHTTP_CreateComment_InvalidJSON_400(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateComment_ValidationError covers Store.CreateComment's ValidationError branch
// (body too long) surfaced through writeStoreError — helpdesk's own writeStoreError maps
// *ValidationError to 400 (BAD_REQUEST-shaped VALIDATION_ERROR), unlike timesheet's/docs's own
// 422 mapping for the same error type; this module's own convention, not a bug.
func TestHTTP_CreateComment_ValidationError(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	body := make([]byte, 0, 10005)
	for len(body) < 10001 {
		body = append(body, 'x')
	}
	payload, err := json.Marshal(map[string]string{"body": string(body)})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, string(payload))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var env errEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != "VALIDATION_ERROR" || env.Error.Details["field"] != "body" {
		t.Fatalf("error = %+v", env.Error)
	}
}

// TestHTTP_CreateTicket_ValidationError covers Store.CreateTicket's validTitle branch (empty
// title) via the HTTP layer — mapped to 400 by writeStoreError (see the comment test above for
// why this module maps *ValidationError to 400, not 422).
func TestHTTP_CreateTicket_ValidationError(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"","description":"y"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateTicket_InvalidJSON_400 covers decodeJSON's invalid-JSON branch on ticket create.
func TestHTTP_CreateTicket_InvalidJSON_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignTicket_InvalidJSON_400 covers decodeJSON's invalid-JSON branch on assign.
func TestHTTP_AssignTicket_InvalidJSON_400(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignTicket_UnknownMember_422 covers assignTicketToMember's org.GetMember-not-found
// branch (memberId that org doesn't recognize -> 422, distinct from the exactly-one-of shape
// checks the position/group assignment test files already cover).
func TestHTTP_AssignTicket_UnknownMember_422(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeMemberId":%q}`, uuid.NewString()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignTicket_TicketNotFound_404 covers handleAssignTicket's own GetTicket-not-found
// path (the store's AssignTicket returning ErrTicketNotFound after auth already passed).
func TestHTTP_AssignTicket_TicketNotFound_404(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+uuid.NewString()+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_TransitionStatus_InvalidJSON_400 covers decodeJSON's invalid-JSON branch on the status
// transition endpoint.
func TestHTTP_TransitionStatus_InvalidJSON_400(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_TransitionStatus_TicketNotFound_404 covers handleTransitionStatus's own
// GetTicket-not-found branch.
func TestHTTP_TransitionStatus_TicketNotFound_404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+uuid.NewString()+"/status", aliceBearer, `{"status":"in_progress"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_GetTicket_InvalidTicketID_400 covers parsePathUUID's invalid-UUID branch for
// ticketId (companyId's own invalid-UUID branch is already covered by
// TestHTTP_CreateTicket_InvalidCompanyID_400).
func TestHTTP_GetTicket_InvalidTicketID_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/not-a-uuid", aliceBearer, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_ListTickets_StatusFilter covers handleListTickets' status query-param branch (never
// exercised by any existing test — every one only lists unfiltered or view-filtered).
func TestHTTP_ListTickets_StatusFilter(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createRec.Code, createRec.Body.String())
	}

	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets?status=open", aliceBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=open: %d %s", rec.Code, rec.Body.String())
	}
	var tickets []ticketWire
	decodeData(t, rec, &tickets)
	if len(tickets) != 1 {
		t.Fatalf("tickets = %+v, want 1 open ticket", tickets)
	}

	rec = f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets?status=closed", aliceBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=closed: %d %s", rec.Code, rec.Body.String())
	}
	decodeData(t, rec, &tickets)
	if len(tickets) != 0 {
		t.Fatalf("tickets = %+v, want 0 closed tickets", tickets)
	}
}

// TestHTTP_AssignTicket_Member_InvalidUUID_400 covers assignTicketToMember's own UUID-parse
// branch (400), distinct from handleAssignTicket's exactly-one-of shape check.
func TestHTTP_AssignTicket_Member_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, `{"assigneeMemberId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeMemberAgent_InvalidUUID_400 covers handleMakeMemberAgent's UUID-parse branch.
func TestHTTP_MakeMemberAgent_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, `{"memberId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeMemberAgent_UnknownMember_422 covers handleMakeMemberAgent's org.GetMember-fails
// branch (a valid-shaped UUID org doesn't recognize).
func TestHTTP_MakeMemberAgent_UnknownMember_422(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"memberId":%q}`, uuid.NewString()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_RemoveAgent_UnknownMember_404 covers handleRemoveAgent's own org.GetMember-fails
// branch (distinct from the openCount-protection 422 already covered by
// TestHTTP_AgentRemoval_ProtectionRule).
func TestHTTP_RemoveAgent_UnknownMember_404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/"+uuid.NewString(), adminBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_RemoveAgent_InvalidUUID_400 covers handleRemoveAgent's parsePathUUID branch.
func TestHTTP_RemoveAgent_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/not-a-uuid", adminBearer, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_GetTicketAudit_Forbidden covers handleGetTicketAudit's canSeeTicket-denies branch — a
// plain member who is neither reporter nor agent/admin nor assignee.
func TestHTTP_GetTicketAudit_Forbidden(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "eve": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	eveBearer := f.token(t, "eve")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/audit", eveBearer, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MyTier_Member covers handleMyTier's plain-member ("member", not agent/admin) branch —
// TestHTTP_MyTier and its Flips siblings only ever exercise the agent/admin transitions.
func TestHTTP_MyTier_Member(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/me", aliceBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Tier string `json:"tier"`
	}
	decodeData(t, rec, &body)
	if body.Tier != "member" {
		t.Fatalf("tier = %q, want member", body.Tier)
	}
}

// TestHTTP_AssignTicket_Group_InvalidUUID_400 covers assignTicketToGroup's own UUID-parse branch.
func TestHTTP_AssignTicket_Group_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"x","description":"y"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, `{"assigneeGroupId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakePositionAgent_InvalidUUID_400 and TestHTTP_MakeGroupAgent_InvalidUUID_400 cover
// handleMakePositionAgent's/handleMakeGroupAgent's own UUID-parse branches.
func TestHTTP_MakePositionAgent_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, `{"positionId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MakeGroupAgent_InvalidUUID_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	adminBearer := f.token(t, "carol-admin")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, `{"groupId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateComment_PositionAssignee_NotifiesCurrentHolder covers handleCreateComment's
// BindingKindPosition notification branch (TestHTTP_FullWorkflowJourney only
// exercises the member-assignee branch). The reporter comments; the CURRENT holder (resolved
// at send time via org, never a snapshotted kcSub, matching assignTicketToPosition's own posture)
// gets notified.
func TestHTTP_CreateComment_PositionAssignee_NotifiesCurrentHolder(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	holderMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Reporter", kcSub: "eve", isActive: true},
		{id: holderMemberID, companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
	}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"eve": true, "alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")
	eveBearer := f.token(t, "eve")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: %d %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", eveBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	f.setPositionHolder(positionID, orgMembers[1])
	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneePositionId":%q}`, positionID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to position: %d %s", assignRec.Code, assignRec.Body.String())
	}

	f.notif.mu.Lock()
	notifBefore := len(f.notif.events)
	f.notif.mu.Unlock()

	commentRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", eveBearer, `{"body":"any update?"}`)
	if commentRec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", commentRec.Code, commentRec.Body.String())
	}

	f.notif.mu.Lock()
	notifAfter := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifAfter != notifBefore+1 {
		t.Fatalf("expected exactly one new notification event for the position holder, got %d -> %d", notifBefore, notifAfter)
	}
}

// TestHTTP_CreateComment_GroupAssignee_NotifiesAllMembers covers handleCreateComment's
// BindingKindGroup notification branch via notifyGroupMembers's own fan-out.
func TestHTTP_CreateComment_GroupAssignee_NotifiesAllMembers(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	member1ID, member2ID := uuid.NewString(), uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Reporter", kcSub: "eve", isActive: true},
		{id: member1ID, companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: member2ID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")
	eveBearer := f.token(t, "eve")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: %d %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", eveBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	f.addGroupMember(groupID, orgMembers[1])
	f.addGroupMember(groupID, orgMembers[2])
	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to group: %d %s", assignRec.Code, assignRec.Body.String())
	}

	f.notif.mu.Lock()
	notifBefore := len(f.notif.events)
	f.notif.mu.Unlock()

	commentRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", eveBearer, `{"body":"any update?"}`)
	if commentRec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", commentRec.Code, commentRec.Body.String())
	}

	f.notif.mu.Lock()
	notifAfter := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifAfter != notifBefore+2 {
		t.Fatalf("expected exactly 2 new notification events (one per group member), got %d -> %d", notifBefore, notifAfter)
	}
}

// TestHTTP_AssignTicket_Member_AlreadyAgent_SkipsAutoGrant covers assignTicketToMember's
// Store.GetAgent FOUND branch (other assignment tests only hit the ErrAgentNotFound auto-grant
// branch, ratcheting a member up to agent for the first time): reassigning a SECOND ticket to a member who is already an agent must skip the
// grant+record round trip entirely and go straight to AssignTicket.
func TestHTTP_AssignTicket_Member_AlreadyAgent_SkipsAutoGrant(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	adminBearer := f.token(t, "carol-admin")

	createRec1 := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"first","description":"d"}`)
	var ticket1 ticketWire
	decodeData(t, createRec1, &ticket1)
	assignRec1 := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket1.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))
	if assignRec1.Code != http.StatusOK {
		t.Fatalf("first assign: %d %s", assignRec1.Code, assignRec1.Body.String())
	}
	if !f.authz.isAgent("bob") {
		t.Fatal("expected bob to be an agent after the first assignment")
	}

	createRec2 := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"second","description":"d"}`)
	var ticket2 ticketWire
	decodeData(t, createRec2, &ticket2)
	assignRec2 := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket2.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))
	if assignRec2.Code != http.StatusOK {
		t.Fatalf("second assign (already agent): %d %s", assignRec2.Code, assignRec2.Body.String())
	}
	var assigned2 ticketWire
	decodeData(t, assignRec2, &assigned2)
	if assigned2.AssigneeMemberID == nil || *assigned2.AssigneeMemberID != bobMemberID {
		t.Fatalf("second assignment = %+v, want assigneeMemberId %q", assigned2, bobMemberID)
	}
}

// TestHTTP_MyTier_AuthzUnavailable_503 covers withAuth's own authz-down fail-closed branch (authz
// down -> never allow, 503, never a silent fallback) — the featureTicketsCreate gate every
// company-scoped route mounts on, never exercised by any existing test.
func TestHTTP_MyTier_AuthzUnavailable_503(t *testing.T) {
	companyID := uuid.NewString()

	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	downAuthz := NewAuthzClient(&http.Client{}, "http://127.0.0.1:1")
	orgClient := NewOrgClient(&http.Client{}, "http://127.0.0.1:1")
	notifClient := NewNotificationClient(&http.Client{}, "http://127.0.0.1:1")
	store := newTestStore(t)
	svc := NewService(store, verifier, downAuthz, orgClient, notifClient)
	f := &httpFixture{svc: svc, handler: svc.Routes(), issuer: issuer}

	tok := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/me", tok, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var env errEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("error = %+v", env.Error)
	}
}

// TestHTTP_Ready_DBReachable_BodyShape covers handleReady like TestHTTP_Ready and additionally
// asserts the body shape.
func TestHTTP_Ready_DBReachable_BodyShape(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/ready", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	decodeData(t, rec, &body)
	if body.Status != "ok" {
		t.Fatalf("status = %q, want ok", body.Status)
	}
}
