// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestHTTP_AssignTicket_ExactlyOneOf_422 proves POST /tickets/{id}/assign rejects both
// assigneeMemberId and assigneePositionId together, and neither at all.
func TestHTTP_AssignTicket_ExactlyOneOf_422(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	memberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "alice"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	bothRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeMemberId":%q,"assigneePositionId":%q}`, memberID, positionID))
	if bothRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("both set: status = %d, want 422, body=%s", bothRec.Code, bothRec.Body.String())
	}
	neitherRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, `{}`)
	if neitherRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("neither set: status = %d, want 422, body=%s", neitherRec.Code, neitherRec.Body.String())
	}
}

// TestHTTP_AssignTicket_UnboundPosition_422 proves assigning a ticket to a position that is NOT
// bound as a helpdesk agent is refused (422 "position is not a helpdesk agent binding") — never
// silently bound as a side effect of assigning one ticket.
func TestHTTP_AssignTicket_UnboundPosition_422(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "alice"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneePositionId":%q}`, positionID))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignTicket_Position_HolderTransitionsFlipOnHandover is the core position scenario:
// position-assign -> the CURRENT holder's transitions ALLOWED, a non-holder agent's assignee-only
// transitions 403 -> handover flips who may transition the SAME ticket, zero helpdesk/authz calls
// between the holder change itself.
func TestHTTP_AssignTicket_Position_HolderTransitionsFlipOnHandover(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	aliceID, bobID := uuid.NewString(), uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Reporter", kcSub: "eve", isActive: true},
		{id: aliceID, companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"eve": true, "alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")
	eveBearer := f.token(t, "eve")
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

	// Bind the position as a helpdesk agent first.
	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", eveBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	// Alice holds the position when the assignment happens.
	f.setPositionHolder(positionID, orgMembers[1])

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneePositionId":%q}`, positionID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to position: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}
	var assigned ticketWire
	decodeData(t, assignRec, &assigned)
	if assigned.AssigneeKind != "position" || assigned.AssigneePositionID == nil || *assigned.AssigneePositionID != positionID {
		t.Fatalf("expected a position-assigned ticket, got %+v", assigned)
	}
	if assigned.AssigneeDisplayName == nil || *assigned.AssigneeDisplayName != "Support Agent — held by Alice" {
		t.Fatalf("expected assigneeDisplayName 'Support Agent — held by Alice', got %v", assigned.AssigneeDisplayName)
	}

	// Alice (the holder) may progress the ticket.
	progressRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"in_progress"}`)
	if progressRec.Code != http.StatusOK {
		t.Fatalf("alice (holder) progress: expected 200, got %d: %s", progressRec.Code, progressRec.Body.String())
	}

	// Bob, a plain member (not the holder), cannot.
	bobDeniedRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"resolved"}`)
	if bobDeniedRec.Code != http.StatusForbidden {
		t.Fatalf("bob (non-holder) transition: expected 403, got %d: %s", bobDeniedRec.Code, bobDeniedRec.Body.String())
	}

	// Handover: alice's tenure ends, bob's begins — zero helpdesk/authz calls between.
	f.clearPositionHolder(positionID)
	f.setPositionHolder(positionID, orgMembers[2])

	// Alice can no longer act.
	aliceDeniedRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"resolved"}`)
	if aliceDeniedRec.Code != http.StatusForbidden {
		t.Fatalf("alice (former holder) transition: expected 403, got %d: %s", aliceDeniedRec.Code, aliceDeniedRec.Body.String())
	}

	// Bob, the new holder, now can — the SAME ticket, zero permission mutations to helpdesk itself.
	bobAllowedRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"resolved"}`)
	if bobAllowedRec.Code != http.StatusOK {
		t.Fatalf("bob (new holder) transition: expected 200, got %d: %s", bobAllowedRec.Code, bobAllowedRec.Body.String())
	}
}

// TestHTTP_AssignTicket_Position_UnassignedChair_NotificationNoOp proves assigning a ticket to a
// position with NO current holder succeeds (200) and fires no notification (no error either) —
// an unassigned chair means no recipient, no error.
func TestHTTP_AssignTicket_Position_UnassignedChair_NotificationNoOp(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true}}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"eve": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneePositionId":%q}`, positionID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to unheld position: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}
	var assigned ticketWire
	decodeData(t, assignRec, &assigned)
	if assigned.AssigneeDisplayName == nil || *assigned.AssigneeDisplayName != "Support Agent" {
		t.Fatalf("expected assigneeDisplayName 'Support Agent' (no holder), got %v", assigned.AssigneeDisplayName)
	}

	f.notif.mu.Lock()
	notifCount := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifCount != 0 {
		t.Fatalf("expected zero notifications for an unassigned chair, got %d", notifCount)
	}
}

// TestHTTP_RemoveAgentForPosition_ProtectionRule proves the removal-protection rule for a
// POSITION binding: refuse while an open ticket is assigned directly to that position (mirror of
// the member path's rule).
func TestHTTP_RemoveAgentForPosition_ProtectionRule(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true}}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"eve": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneePositionId":%q}`, positionID)); rec.Code != http.StatusOK {
		t.Fatalf("assign to position: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	removeRec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/positions/"+positionID, adminBearer, "")
	if removeRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 (protection rule), got %d: %s", removeRec.Code, removeRec.Body.String())
	}
}

// TestHTTP_AssignablePositions_ManageGate403ForPlainAgent proves GET .../assignable-positions is
// helpdesk.manage-gated — a plain agent (not an admin) is refused.
func TestHTTP_AssignablePositions_ManageGate403ForPlainAgent(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"bob": true}, nil, nil)
	// bob is a member but neither admin nor agent; the route mounts on featureHelpdeskManage
	// directly (admin only, same as /agents itself) — plain membership or even the agent tier is
	// insufficient.
	bobBearer := f.token(t, "bob")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/assignable-positions", bobBearer, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignablePositions_LeastDisclosureShape proves the route returns ONLY agent-bound
// positions (never the org chart at large), with the current holder resolved — and an unbound
// position never appears, (least disclosure: the assign target set, not the
// org chart).
func TestHTTP_AssignablePositions_LeastDisclosureShape(t *testing.T) {
	companyID := uuid.NewString()
	boundPositionID := uuid.NewString()
	unboundPositionID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{
			{id: boundPositionID, companyID: companyID, title: "Support Agent"},
			{id: unboundPositionID, companyID: companyID, title: "Unbound Chair"},
		})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, boundPositionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	f.setPositionHolder(boundPositionID, orgMembers[0])

	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/assignable-positions", adminBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rows []assignablePositionWire
	decodeData(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 assignable position (the bound one), got %+v", rows)
	}
	if rows[0].PositionID != boundPositionID || rows[0].Title != "Support Agent" {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
	if rows[0].HolderDisplayName == nil || *rows[0].HolderDisplayName != "Alice" {
		t.Fatalf("expected holderDisplayName=Alice, got %v", rows[0].HolderDisplayName)
	}
}

// TestHTTP_AssignTicket_Member_ClearsAnyPriorPositionAssignment proves the exactly-one-of
// invariant holds across re-assignment: a ticket previously assigned to a position, then
// re-assigned to a member, no longer carries a position assignee.
func TestHTTP_AssignTicket_Member_ClearsAnyPriorPositionAssignment(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	bobID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
		{id: bobID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithPositions(t, map[string]bool{"eve": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Agent"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneePositionId":%q}`, positionID))

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobID))
	if rec.Code != http.StatusOK {
		t.Fatalf("re-assign to member: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var reassigned ticketWire
	decodeData(t, rec, &reassigned)
	if reassigned.AssigneeKind != "member" || reassigned.AssigneePositionID != nil {
		t.Fatalf("expected the position assignee cleared, got %+v", reassigned)
	}
}
