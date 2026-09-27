// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestHTTP_MakeAgent_ExactlyOneOf_422 proves POST /agents rejects both memberId and positionId
// together, and neither at all.
func TestHTTP_MakeAgent_ExactlyOneOf_422(t *testing.T) {
	companyID := uuid.NewString()
	memberID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")

	bothRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer,
		fmt.Sprintf(`{"memberId":%q,"positionId":%q}`, memberID, positionID))
	if bothRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("both set: status = %d, want 422, body=%s", bothRec.Code, bothRec.Body.String())
	}

	neitherRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, `{}`)
	if neitherRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("neither set: status = %d, want 422, body=%s", neitherRec.Code, neitherRec.Body.String())
	}
}

// TestHTTP_MakeAgent_Position_CompanyMismatch422 proves a position belonging to a DIFFERENT
// company than the caller's route is refused (422), never silently bound cross-company.
func TestHTTP_MakeAgent_Position_CompanyMismatch422(t *testing.T) {
	companyID := uuid.NewString()
	otherCompanyID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: otherCompanyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeAgent_Position_UnknownPosition422 proves a positionId that doesn't resolve to a
// real position (org 404s) is a 422, not a 5xx or a silently-accepted bind.
func TestHTTP_MakeAgent_Position_UnknownPosition422(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil, nil)
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, uuid.NewString()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MakeAgent_Position_HolderGetsAndLosesAccess is the core position scenario: position bind
// -> the CURRENT holder's tickets.work ALLOWS; the position's holder changing (org's own
// assign/end, simulated here via setPositionHolder/clearPositionHolder — ZERO helpdesk/authz
// calls between) flips who has access with NO additional grant/revoke call to helpdesk at all —
// the "successor inherits the position's access" property, at the granularity this module's own
// fake-authz double can prove (internal/authz's differential harness and live tests cover the
// real engine chain, and the e2e suite covers it through the real UI).
func TestHTTP_MakeAgent_Position_HolderGetsAndLosesAccess(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")

	makeRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID))
	if makeRec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", makeRec.Code, makeRec.Body.String())
	}
	var bound agentWire
	decodeData(t, makeRec, &bound)
	if bound.BindingKind != BindingKindPosition || bound.PositionID == nil || *bound.PositionID != positionID {
		t.Fatalf("expected a position-bound agent row, got %+v", bound)
	}
	if bound.PositionTitle == nil || *bound.PositionTitle != "Support Lead" {
		t.Fatalf("expected the position_title snapshot, got %+v", bound)
	}

	// Nobody holds the position yet: no one has access via it.
	if f.authz.isAgent("alice") {
		t.Fatal("alice should not be an agent before holding the position")
	}

	// Alice is assigned (org's own fact-layer call — zero permission mutations here).
	f.authz.setPositionHolder(positionID, "alice")
	if !f.authz.isAgent("alice") {
		t.Fatal("alice should be an agent while holding the bound position")
	}

	// Alice's assignment ends, Bob's begins — same-day handover, zero permission mutations.
	f.authz.clearPositionHolder(positionID)
	f.authz.setPositionHolder(positionID, "bob")
	if f.authz.isAgent("alice") {
		t.Fatal("alice should LOSE access once she no longer holds the position")
	}
	if !f.authz.isAgent("bob") {
		t.Fatal("bob should gain access as the position's new holder")
	}
}

// TestHTTP_ListAgents_BindingKindPosition proves GET /agents rows carry bindingKind="position"
// for a position-bound row (alongside "member" for the pre-existing shape).
func TestHTTP_ListAgents_BindingKindPosition(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, "")
	var agents []agentWire
	decodeData(t, listRec, &agents)
	if len(agents) != 1 || agents[0].BindingKind != BindingKindPosition {
		t.Fatalf("expected exactly 1 position-bound agent, got %+v", agents)
	}
}

// TestHTTP_RemoveAgentForPosition_Success proves the NEW DELETE /agents/positions/{positionId}
// route revokes the tuple AND the index row — the (still-)holder loses access even without org
// ever ending the assignment, and the row disappears from GET /agents.
func TestHTTP_RemoveAgentForPosition_Success(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	f.authz.setPositionHolder(positionID, "alice")
	if !f.authz.isAgent("alice") {
		t.Fatal("alice should be an agent while holding the bound position")
	}

	removeRec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/positions/"+positionID, adminBearer, "")
	if removeRec.Code != http.StatusNoContent {
		t.Fatalf("remove position binding: status = %d, want 204, body=%s", removeRec.Code, removeRec.Body.String())
	}
	if f.authz.isAgent("alice") {
		t.Fatal("alice should lose access once the position binding itself is revoked")
	}

	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, "")
	var agents []agentWire
	decodeData(t, listRec, &agents)
	if len(agents) != 0 {
		t.Fatalf("expected no agents left after revoke, got %+v", agents)
	}
}

// TestHTTP_RemoveAgentForPosition_NotFound404 proves revoking a binding that was never created
// 404s, matching the member path's own not-found handling.
func TestHTTP_RemoveAgentForPosition_NotFound404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t, map[string]bool{"carol-admin": true}, map[string]bool{"carol-admin": true}, nil, nil)
	adminBearer := f.token(t, "carol-admin")

	rec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/positions/"+uuid.NewString(), adminBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_MyTier_FlipsWithPositionHolder proves, for helpdesk's OWN /me
// endpoint: the decision path the UI actually reads (GET /me -> svc.tier -> AuthzClient.Can,
// never the effective-access summary's objectAccess, which stays direct-tuples-only by design),
// that the tier flips "member" -> "agent" -> "member" as the bound position's holder
// changes, with ZERO additional helpdesk/authz calls between the holder changes themselves
// (setPositionHolder/clearPositionHolder stand in for org's own AssignNow/EndAssignment, proven
// for real in internal/authz's TestDecisionEngineRelationCheck_PositionHolderFlip).
func TestHTTP_MyTier_FlipsWithPositionHolder(t *testing.T) {
	companyID := uuid.NewString()
	positionID := uuid.NewString()
	f := newHTTPFixtureWithPositions(t,
		map[string]bool{"carol-admin": true, "alice": true, "bob": true}, map[string]bool{"carol-admin": true}, nil,
		[]fakeOrgPosition{{id: positionID, companyID: companyID, title: "Support Lead"}})
	adminBearer := f.token(t, "carol-admin")
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

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

	if rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"positionId":%q}`, positionID)); rec.Code != http.StatusCreated {
		t.Fatalf("bind position: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := myTier(aliceBearer); got != "member" {
		t.Fatalf("alice's tier before HOLDING the bound position = %q, want member", got)
	}

	f.authz.setPositionHolder(positionID, "alice")
	if got := myTier(aliceBearer); got != "agent" {
		t.Fatalf("alice's tier while holding the bound position = %q, want agent", got)
	}

	// Same-day handover: end alice, assign bob — zero helpdesk/authz calls between.
	f.authz.clearPositionHolder(positionID)
	f.authz.setPositionHolder(positionID, "bob")
	if got := myTier(aliceBearer); got != "member" {
		t.Fatalf("alice's tier after the handover = %q, want member (she lost it)", got)
	}
	if got := myTier(bobBearer); got != "agent" {
		t.Fatalf("bob's tier after the handover = %q, want agent (he inherited it)", got)
	}
}
