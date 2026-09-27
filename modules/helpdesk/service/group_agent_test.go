// SPDX-License-Identifier: Apache-2.0

// Group agent-binding coverage — the group sibling of position_agent_test.go, adapted
// for the "multiple simultaneous members, no single holder" difference (fakeOrg/fakeAuthz's own
// groupMembers/groupMember are SETS, addGroupMember/removeGroupMember rather than
// setPositionHolder/clearPositionHolder).
package helpdesk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestHTTP_MakeAgent_ExactlyOneOfThree_422 proves POST /agents rejects any combination other than
// exactly one of {memberId, positionId, groupId}.
func TestHTTP_MakeAgent_ExactlyOneOfThree_422(t *testing.T) {
	companyID := uuid.NewString()
	memberID := uuid.NewString()
	positionID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithPositionsAndGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}},
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	allThreeRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer,
		fmt.Sprintf(`{"memberId":%q,"positionId":%q,"groupId":%q}`, memberID, positionID, groupID))
	if allThreeRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("all three set: status = %d, want 422, body=%s", allThreeRec.Code, allThreeRec.Body.String())
	}

	memberAndGroupRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer,
		fmt.Sprintf(`{"memberId":%q,"groupId":%q}`, memberID, groupID))
	if memberAndGroupRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("member+group set: status = %d, want 422, body=%s", memberAndGroupRec.Code, memberAndGroupRec.Body.String())
	}

	neitherRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, `{}`)
	if neitherRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("neither set: status = %d, want 422, body=%s", neitherRec.Code, neitherRec.Body.String())
	}
}

// TestHTTP_MakeAgent_Group_CompanyMismatch422 proves a group belonging to a DIFFERENT company
// than the caller's route is refused (422), never silently bound cross-company.
func TestHTTP_MakeAgent_Group_CompanyMismatch422(t *testing.T) {
	companyID := uuid.NewString()
	otherCompanyID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgGroup{{id: groupID, companyID: otherCompanyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeAgent_Group_UnknownGroup422 proves a groupId that doesn't resolve to a real group
// (org 404s) is a 422, not a 5xx or a silently-accepted bind.
func TestHTTP_MakeAgent_Group_UnknownGroup422(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil, nil)
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, uuid.NewString()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeAgent_Group_MultipleMembersAllGetAccess is the core group scenario: group bind ->
// EVERY current member's tickets.work ALLOWS, simultaneously (unlike position's single holder).
// Removing one member drops only THEIR access; the others keep it — proving the mechanism holds
// membership as a set, not a single fact.
func TestHTTP_MakeAgent_Group_MultipleMembersAllGetAccess(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	makeRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID))
	if makeRec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", makeRec.Code, makeRec.Body.String())
	}
	var bound agentWire
	decodeData(t, makeRec, &bound)
	if bound.BindingKind != BindingKindGroup || bound.GroupID == nil || *bound.GroupID != groupID {
		t.Fatalf("expected a group-bound agent row, got %+v", bound)
	}
	if bound.GroupTitle == nil || *bound.GroupTitle != "Support Team" {
		t.Fatalf("expected the group name snapshot, got %+v", bound)
	}

	alice := fakeOrgMember{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}
	bob := fakeOrgMember{id: uuid.NewString(), companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}

	// Nobody is a member yet: no one has access via the group.
	if f.authz.isAgent("alice") || f.authz.isAgent("bob") {
		t.Fatal("nobody should be an agent before joining the bound group")
	}

	// Alice AND bob join (org's own fact-layer call — zero permission mutations here) —
	// simultaneously, unlike position's replacement semantics.
	f.addGroupMember(groupID, alice)
	f.addGroupMember(groupID, bob)
	if !f.authz.isAgent("alice") || !f.authz.isAgent("bob") {
		t.Fatal("both alice and bob should be agents while members of the bound group")
	}

	// Removing bob drops ONLY his access.
	f.removeGroupMember(groupID, bob)
	if f.authz.isAgent("bob") {
		t.Fatal("bob should LOSE access once he's no longer a group member")
	}
	if !f.authz.isAgent("alice") {
		t.Fatal("alice should KEEP her access — removing bob must not affect other members")
	}
}

// TestHTTP_ListAgents_BindingKindGroup proves GET /agents rows carry bindingKind="group" for a
// group-bound row (alongside "member"/"position" for the other two shapes).
func TestHTTP_ListAgents_BindingKindGroup(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, "")
	var agents []agentWire
	decodeData(t, listRec, &agents)
	if len(agents) != 1 || agents[0].BindingKind != BindingKindGroup {
		t.Fatalf("expected exactly 1 group-bound agent, got %+v", agents)
	}
}

// TestHTTP_RemoveAgentForGroup_Success proves DELETE /agents/groups/{groupId} revokes the tuple
// AND the index row — every (still-)member loses access even without org ever removing the
// membership, and the row disappears from GET /agents.
func TestHTTP_RemoveAgentForGroup_Success(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	alice := fakeOrgMember{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}
	f.addGroupMember(groupID, alice)
	if !f.authz.isAgent("alice") {
		t.Fatal("alice should be an agent while a member of the bound group")
	}

	removeRec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/groups/"+groupID, adminBearer, "")
	if removeRec.Code != http.StatusNoContent {
		t.Fatalf("remove group binding: status = %d, want 204, body=%s", removeRec.Code, removeRec.Body.String())
	}
	if f.authz.isAgent("alice") {
		t.Fatal("alice should lose access once the group binding itself is revoked")
	}

	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, "")
	var agents []agentWire
	decodeData(t, listRec, &agents)
	if len(agents) != 0 {
		t.Fatalf("expected no agents left after revoke, got %+v", agents)
	}
}

// TestHTTP_RemoveAgentForGroup_NotFound404 proves revoking a binding that was never created 404s.
func TestHTTP_RemoveAgentForGroup_NotFound404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil, nil)
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/groups/"+uuid.NewString(), adminBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MyTier_FlipsWithGroupMembership is the group sibling of
// TestHTTP_MyTier_FlipsWithPositionHolder: the decision path helpdesk's OWN /me endpoint reads
// flips "member" -> "agent" -> "member" as group membership changes, with ZERO additional
// helpdesk/authz calls between the membership changes themselves.
func TestHTTP_MyTier_FlipsWithGroupMembership(t *testing.T) {
	companyID := uuid.NewString()
	groupID := uuid.NewString()
	f := newHTTPFixtureWithGroups(t,
		map[string]bool{"carol-admin": true, "alice": true, "bob": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgGroup{{id: groupID, companyID: companyID, name: "Support Team"}})
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")
	alice := fakeOrgMember{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}
	bob := fakeOrgMember{id: uuid.NewString(), companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}

	myTier := func(bearer string) string {
		rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/me", bearer, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /me: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body struct {
			Tier string `json:"tier"`
		}
		decodeData(t, rec, &body)
		return body.Tier
	}

	if got := myTier(aliceBearer); got != "member" {
		t.Fatalf("alice's tier before any binding = %q, want member", got)
	}

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"groupId":%q}`, groupID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := myTier(aliceBearer); got != "member" {
		t.Fatalf("alice's tier before JOINING the bound group = %q, want member", got)
	}

	f.addGroupMember(groupID, alice)
	f.addGroupMember(groupID, bob)
	if got := myTier(aliceBearer); got != "agent" {
		t.Fatalf("alice's tier while a member of the bound group = %q, want agent", got)
	}
	if got := myTier(bobBearer); got != "agent" {
		t.Fatalf("bob's tier while a member of the bound group = %q, want agent", got)
	}

	f.removeGroupMember(groupID, bob)
	if got := myTier(bobBearer); got != "member" {
		t.Fatalf("bob's tier after leaving the group = %q, want member (he lost it)", got)
	}
	if got := myTier(aliceBearer); got != "agent" {
		t.Fatalf("alice's tier after bob left = %q, want agent (unaffected)", got)
	}
}
