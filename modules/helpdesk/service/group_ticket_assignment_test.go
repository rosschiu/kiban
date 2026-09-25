// SPDX-License-Identifier: Apache-2.0

// Group ticket-assignment coverage — the group sibling of
// position_ticket_assignment_test.go, adapted for the "multiple simultaneous members, notification
// fan-out instead of a single holder" difference.
package helpdesk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestHTTP_AssignTicket_UnboundGroup_422 proves assigning a ticket to a group that is NOT bound as
// a helpdesk agent is refused (422 "group is not a helpdesk agent binding") — never silently
// bound as a side effect of assigning one ticket.
func TestHTTP_AssignTicket_UnboundGroup_422(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "alice"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignTicket_Group_BothMembersWorkItRemoveOneLosesIt is the core group scenario
// (mirrors the walkthrough's own "Support Team" step): group-assign -> BOTH alice and bob (group
// members) may view/transition the SAME ticket simultaneously; removing bob from the group flips
// ONLY his access — alice keeps hers — with ZERO helpdesk/authz calls between the membership
// change itself.
func TestHTTP_AssignTicket_Group_BothMembersWorkItRemoveOneLosesIt(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	aliceID, bobID := uuid.NewString(), uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Reporter", kcSub: "eve", isActive: true},
		{id: aliceID, companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")
	eveBearer := f.token(t, "eve")
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

	// Bind the group as a helpdesk agent first, and seed both members BEFORE assignment (mirrors
	// the walkthrough: alice+bob already in "Support Team" when the ticket is assigned to it).
	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	f.addGroupMember(groupID, orgMembers[1]) // alice
	f.addGroupMember(groupID, orgMembers[2]) // bob

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", eveBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to group: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}
	var assigned ticketWire
	decodeData(t, assignRec, &assigned)
	if assigned.AssigneeKind != "group" || assigned.AssigneeGroupID == nil || *assigned.AssigneeGroupID != groupID {
		t.Fatalf("expected a group-assigned ticket, got %+v", assigned)
	}

	// BOTH alice and bob (current group members) may progress the ticket — simultaneously, unlike
	// position's single-holder exclusivity.
	aliceProgressRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"in_progress"}`)
	if aliceProgressRec.Code != http.StatusOK {
		t.Fatalf("alice (group member) progress: expected 200, got %d: %s", aliceProgressRec.Code, aliceProgressRec.Body.String())
	}

	getBobRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID, bobBearer, "")
	if getBobRec.Code != http.StatusOK {
		t.Fatalf("bob (group member) view: expected 200, got %d: %s", getBobRec.Code, getBobRec.Body.String())
	}

	// Remove bob from the group — zero helpdesk/authz calls beyond the membership change itself.
	f.removeGroupMember(groupID, orgMembers[2])

	// Bob can no longer act on the ticket.
	bobDeniedRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"resolved"}`)
	if bobDeniedRec.Code != http.StatusForbidden {
		t.Fatalf("bob (removed member) transition: expected 403, got %d: %s", bobDeniedRec.Code, bobDeniedRec.Body.String())
	}

	// Alice, still a member, keeps her access to the SAME ticket.
	aliceAllowedRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"resolved"}`)
	if aliceAllowedRec.Code != http.StatusOK {
		t.Fatalf("alice (remaining member) transition: expected 200, got %d: %s", aliceAllowedRec.Code, aliceAllowedRec.Body.String())
	}
}

// TestHTTP_AssignTicket_Group_NotificationFanOutToAllMembers proves the one behavioral divergence
// from the position path's single-holder notification: assigning to a group fans out ONE
// notification event per current member with a linked user — an empty/all-unlinked group is a
// legitimate, non-error no-op.
func TestHTTP_AssignTicket_Group_NotificationFanOutToAllMembers(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	f.addGroupMember(groupID, orgMembers[1]) // alice
	f.addGroupMember(groupID, orgMembers[2]) // bob

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to group: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}

	f.notif.mu.Lock()
	notifCount := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifCount != 2 {
		t.Fatalf("expected 2 notifications (one per current member), got %d", notifCount)
	}
}

// TestHTTP_AssignTicket_Group_EmptyGroup_NotificationNoOp proves assigning to a group with no
// current members succeeds (200) and fires no notification — the group sibling of
// TestHTTP_AssignTicket_Position_UnassignedChair_NotificationNoOp.
func TestHTTP_AssignTicket_Group_EmptyGroup_NotificationNoOp(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true}}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign to empty group: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}

	f.notif.mu.Lock()
	notifCount := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifCount != 0 {
		t.Fatalf("expected zero notifications for an empty group, got %d", notifCount)
	}
}

// TestHTTP_RemoveAgentForGroup_ProtectionRule proves the group binding's own removal-protection
// rule: refuse while an open ticket is assigned directly to that group (mirror of the
// position/member path's rule).
func TestHTTP_RemoveAgentForGroup_ProtectionRule(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true}}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID)); rec.Code != http.StatusOK {
		t.Fatalf("assign to group: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	removeRec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/groups/"+groupID, adminBearer, "")
	if removeRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 (protection rule), got %d: %s", removeRec.Code, removeRec.Body.String())
	}
}

// TestHTTP_AssignablGroups_ManageGate403ForPlainAgent proves GET .../assignable-groups is
// helpdesk.manage-gated.
func TestHTTP_AssignableGroups_ManageGate403ForPlainAgent(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"bob": true}, nil, nil)
	bobBearer := f.token(t, "bob")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/assignable-groups", bobBearer, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AssignableGroups_LeastDisclosureShape proves the route returns ONLY agent-bound groups
// with a member count, and an unbound group never appears — the group sibling of
// TestHTTP_AssignablePositions_LeastDisclosureShape.
func TestHTTP_AssignableGroups_LeastDisclosureShape(t *testing.T) {
	companyID := uuid.NewString()
	boundGroupID := uuid.NewString()
	unboundGroupID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{
			{id: boundGroupID, companyID: companyID, name: "Support Team"},
			{id: unboundGroupID, companyID: companyID, name: "Unbound Group"},
		})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, boundGroupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	f.addGroupMember(boundGroupID, orgMembers[0])
	f.addGroupMember(boundGroupID, orgMembers[1])

	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/assignable-groups", adminBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rows []assignableGroupWire
	decodeData(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 assignable group (the bound one), got %+v", rows)
	}
	if rows[0].GroupID != boundGroupID || rows[0].Title != "Support Team" {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
	if rows[0].MemberCount != 2 {
		t.Fatalf("expected memberCount=2, got %d", rows[0].MemberCount)
	}
}

// TestHTTP_AssignTicket_Member_ClearsAnyPriorGroupAssignment proves the at-most-one-of invariant
// holds across re-assignment: a ticket previously assigned to a group, then re-assigned to a
// member, no longer carries a group assignee.
func TestHTTP_AssignTicket_Member_ClearsAnyPriorGroupAssignment(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	bobID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
		{id: bobID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixtureWithGroups(t, map[string]bool{"eve": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", f.token(t, "eve"), `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeGroupId":%q}`, groupID))

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobID))
	if rec.Code != http.StatusOK {
		t.Fatalf("re-assign to member: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var reassigned ticketWire
	decodeData(t, rec, &reassigned)
	if reassigned.AssigneeKind != "member" || reassigned.AssigneeGroupID != nil {
		t.Fatalf("expected the group assignee cleared, got %+v", reassigned)
	}
}
