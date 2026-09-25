// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testopenapi"
)

// ---- fake authz server ------------------------------------------------------------------------
//
// Stands in for authz's own effective-access/grants surface (mocks only for
// genuinely external systems). Models the REAL base-model company_module union this module
// relies on (internal/authz/engine/model.json): #editor = this OR #admin, so an admin is always
// also an "agent" in Can(helpdesk.tickets.work) terms — the fake replicates that union rather
// than tracking it as a separate, disconnected fact.

type fakeAuthz struct {
	mu      sync.Mutex
	admins  map[string]bool // kcSub -> holds company_module#admin (direct grant, test fixture)
	agents  map[string]bool // kcSub -> holds company_module#editor (direct grant via GrantAgent)
	members map[string]bool // kcSub -> active company member (steps 1-6 gate)

	// Models the position -> member -> user chain at the granularity
	// this fake needs, WITHOUT re-implementing the engine's own recursive evaluation (that's
	// internal/authz's own job, proven by the differential harness/live tests): positionEditor
	// tracks which positions currently hold `company_module#editor` (GrantPositionAgent's tuple);
	// positionHolder tracks which kcSub currently holds each position (test-configurable, mirrors
	// org's own AssignNow/EndAssignment — set/cleared directly by the test, never by an authz
	// call, since org isn't in this fake's scope either).
	positionEditor map[string]bool   // positionID -> holds company_module#editor (direct grant via GrantPositionAgent)
	positionHolder map[string]string // positionID -> kcSub of the CURRENT holder ("" / absent = no holder)

	// Models the group -> member -> user chain at the granularity this fake needs,
	// mirroring positionEditor/positionHolder above — groupEditor tracks which groups currently
	// hold `company_module#editor` (GrantGroupAgent's tuple); groupMember tracks which kcSubs are
	// CURRENT members of each group (test-configurable, mirrors org's own AddGroupMember/
	// RemoveGroupMember — set/cleared directly by the test). Unlike position, a group can have
	// MULTIPLE simultaneous members.
	groupEditor map[string]bool            // groupID -> holds company_module#editor (direct grant via GrantGroupAgent)
	groupMember map[string]map[string]bool // groupID -> set of kcSubs currently members
}

func newFakeAuthz(members map[string]bool, admins map[string]bool) *fakeAuthz {
	if admins == nil {
		admins = map[string]bool{}
	}
	return &fakeAuthz{
		admins: admins, agents: map[string]bool{}, members: members,
		positionEditor: map[string]bool{}, positionHolder: map[string]string{},
		groupEditor: map[string]bool{}, groupMember: map[string]map[string]bool{},
	}
}

// addGroupMember/removeGroupMember simulate org's Store.AddGroupMember/RemoveGroupMember: a fact
// change ONLY, zero permission-tuple edits — the whole point of the mechanism (an
// ALREADY-granted group:*#member tuple in company_module#editor resolves to every current
// member's kcSub, with no re-grant needed as membership changes).
func (f *fakeAuthz) addGroupMember(groupID, kcSub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groupMember[groupID] == nil {
		f.groupMember[groupID] = map[string]bool{}
	}
	f.groupMember[groupID][kcSub] = true
}

func (f *fakeAuthz) removeGroupMember(groupID, kcSub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groupMember[groupID], kcSub)
}

// setPositionHolder simulates org's Store.AssignNow: kcSub becomes positionID's
// current holder — a fact change ONLY, zero permission-tuple edits (the whole point of the
// mechanism: an ALREADY-granted position:*#holder tuple in company_module#editor just resolves
// to a different kcSub once the member-bridge tuple points elsewhere).
func (f *fakeAuthz) setPositionHolder(positionID, kcSub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.positionHolder[positionID] = kcSub
}

// clearPositionHolder simulates org's Store.EndAssignment.
func (f *fakeAuthz) clearPositionHolder(positionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.positionHolder, positionID)
}

func (f *fakeAuthz) isAgent(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agents[sub] || f.admins[sub] { // union: editor = this OR admin
		return true
	}
	for positionID, granted := range f.positionEditor {
		if granted && f.positionHolder[positionID] == sub {
			return true
		}
	}
	for groupID, granted := range f.groupEditor {
		if granted && f.groupMember[groupID][sub] {
			return true
		}
	}
	return false
}

func (f *fakeAuthz) isAdmin(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.admins[sub]
}

func (f *fakeAuthz) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/authz/effective-access/can", func(w http.ResponseWriter, r *http.Request) {
		sub := subjectFromBearer(r.Header.Get("Authorization"))
		var req struct {
			FeatureKey string `json:"featureKey"`
			Relation   string `json:"relation"`
			Object     struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"object"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// The OBJECT-MODE check (AuthzClient.IsPositionHolder) — "does sub currently
		// hold position <Object.ID>?" — is a DIFFERENT question from the tier checks below (an
		// agent via SOME means is not necessarily THIS ticket's assigned position's holder), so it
		// is checked first, against positionHolder directly, never routed through isAgent.
		if req.Object.Type == "position" && req.Relation == "holder" {
			f.mu.Lock()
			allowed := f.positionHolder[req.Object.ID] == sub && sub != ""
			f.mu.Unlock()
			reason := "ENGINE_DENIED"
			if allowed {
				reason = "ALLOWED"
			}
			writeJSON(w, map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
			return
		}
		// The OBJECT-MODE check (AuthzClient.IsGroupMember) — "is sub CURRENTLY a
		// member of group <Object.ID>?" — same posture as the position leg above, checked directly
		// against groupMember, never routed through isAgent.
		if req.Object.Type == "group" && req.Relation == "member" {
			f.mu.Lock()
			allowed := f.groupMember[req.Object.ID][sub] && sub != ""
			f.mu.Unlock()
			reason := "ENGINE_DENIED"
			if allowed {
				reason = "ALLOWED"
			}
			writeJSON(w, map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
			return
		}

		var allowed bool
		switch req.FeatureKey {
		case featureHelpdeskManage:
			allowed = f.isAdmin(sub)
		case featureTicketsWork:
			allowed = f.isAgent(sub)
		default: // helpdesk.tickets.create and any other feature-only check: membership only
			f.mu.Lock()
			allowed = f.members[sub]
			f.mu.Unlock()
		}
		reason := "ENGINE_DENIED"
		if allowed {
			reason = "ALLOWED"
		}
		writeJSON(w, map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
	})
	mux.HandleFunc("POST /internal/authz/grants", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Op        string `json:"op"`
			CompanyID string `json:"companyId"`
			Tuples    []struct {
				Relation        string `json:"relation"`
				SubjectType     string `json:"subjectType"`
				SubjectID       string `json:"subjectId"`
				SubjectRelation string `json:"subjectRelation"`
			} `json:"tuples"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CompanyID == "" { // the real endpoint requires companyId
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		for _, tp := range req.Tuples {
			if tp.Relation != "editor" {
				continue
			}
			switch tp.SubjectType {
			case "position":
				if req.Op == "grant" {
					f.positionEditor[tp.SubjectID] = true
				} else {
					delete(f.positionEditor, tp.SubjectID)
				}
			case "group":
				if req.Op == "grant" {
					f.groupEditor[tp.SubjectID] = true
				} else {
					delete(f.groupEditor, tp.SubjectID)
				}
			default: // "user"
				if req.Op == "grant" {
					f.agents[tp.SubjectID] = true
				} else {
					delete(f.agents, tp.SubjectID)
				}
			}
		}
		f.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{"status": "ok", "count": len(req.Tuples)}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func subjectFromBearer(authHeader string) string {
	token := bearerFromHeader(authHeader)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

// ---- fake org server ----------------------------------------------------------------------------

type fakeOrgMember struct {
	id, companyID, displayName, kcSub string
	isActive                          bool
}

func newFakeOrg(t *testing.T, members []fakeOrgMember) *fakeOrg {
	t.Helper()
	return newFakeOrgWithPositions(t, members, nil)
}

// fakeOrgPosition is part of the fake org double: GetPosition's company-match
// resolution needs a position's own companyId/title, the same shape org's real
// GET /internal/org/positions/{id} returns.
type fakeOrgPosition struct {
	id, companyID, title string
}

// fakeOrgGroup is part of the fake org double: OrgClient.GetGroup's company-match
// resolution needs a group's own companyId/name, the same shape org's real
// GET /internal/org/groups/{id} returns.
type fakeOrgGroup struct {
	id, companyID, name string
}

// fakeOrg wraps an *httptest.Server with mutable state: OrgClient.GetPositionHolder needs
// a MUTABLE "who holds position P today" fact org's own AssignNow/EndAssignment would maintain —
// setHolder/clearHolder are this fake's stand-in, mirroring fakeAuthz's own
// setPositionHolder/clearPositionHolder for the SAME underlying fact (kept in sync by
// httpFixture.setPositionHolder, which updates both doubles in one call). The
// group sibling: groupMembers is a SET (a group has many members, unlike position's one holder).
type fakeOrg struct {
	mu           sync.Mutex
	byID         map[string]fakeOrgMember
	holder       map[string]string // positionID -> memberID currently holding it ("" / absent = unassigned)
	groupsByID   map[string]fakeOrgGroup
	groupMembers map[string]map[string]bool // groupID -> set of memberIDs currently members
	url          string
}

func (o *fakeOrg) setHolder(positionID, memberID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.holder[positionID] = memberID
}

func (o *fakeOrg) clearHolder(positionID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.holder, positionID)
}

func (o *fakeOrg) addGroupMember(groupID, memberID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.groupMembers[groupID] == nil {
		o.groupMembers[groupID] = map[string]bool{}
	}
	o.groupMembers[groupID][memberID] = true
}

func (o *fakeOrg) removeGroupMember(groupID, memberID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.groupMembers[groupID], memberID)
}

func newFakeOrgWithPositions(t *testing.T, members []fakeOrgMember, positions []fakeOrgPosition) *fakeOrg {
	t.Helper()
	return newFakeOrgWithPositionsAndGroups(t, members, positions, nil)
}

func newFakeOrgWithPositionsAndGroups(t *testing.T, members []fakeOrgMember, positions []fakeOrgPosition, groups []fakeOrgGroup) *fakeOrg {
	t.Helper()
	byID := map[string]fakeOrgMember{}
	byKcSub := map[string]fakeOrgMember{}
	for _, m := range members {
		byID[m.id] = m
		if m.kcSub != "" {
			byKcSub[m.kcSub] = m
		}
	}
	posByID := map[string]fakeOrgPosition{}
	for _, p := range positions {
		posByID[p.id] = p
	}
	groupsByID := map[string]fakeOrgGroup{}
	for _, g := range groups {
		groupsByID[g.id] = g
	}
	fo := &fakeOrg{byID: byID, holder: map[string]string{}, groupsByID: groupsByID, groupMembers: map[string]map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/org/members/{id}", func(w http.ResponseWriter, r *http.Request) {
		m, ok := byID[r.PathValue("id")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var userField any
		if m.kcSub != "" {
			userField = map[string]any{"kcSub": m.kcSub}
		}
		writeJSON(w, map[string]any{"data": map[string]any{
			"id": m.id, "companyId": m.companyID, "displayName": m.displayName, "isActive": m.isActive, "user": userField,
		}})
	})
	mux.HandleFunc("GET /internal/org/companies/{companyId}/members/by-kcsub/{kcSub}", func(w http.ResponseWriter, r *http.Request) {
		m, ok := byKcSub[r.PathValue("kcSub")]
		if !ok || m.companyID != r.PathValue("companyId") {
			writeJSON(w, map[string]any{"data": map[string]any{"isMember": false, "isActive": false}})
			return
		}
		id := m.id
		writeJSON(w, map[string]any{"data": map[string]any{"isMember": true, "isActive": m.isActive, "memberId": id}})
	})
	mux.HandleFunc("GET /internal/org/positions/{id}/holder", func(w http.ResponseWriter, r *http.Request) {
		fo.mu.Lock()
		memberID, ok := fo.holder[r.PathValue("id")]
		fo.mu.Unlock()
		if !ok || memberID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"memberId": memberID}})
	})
	mux.HandleFunc("GET /internal/org/positions/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := posByID[r.PathValue("id")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{
			"id": p.id, "companyId": p.companyID, "code": "POS", "title": p.title, "orgUnitId": p.companyID,
		}})
	})
	mux.HandleFunc("GET /internal/org/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupsByID[r.PathValue("id")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{
			"id": g.id, "companyId": g.companyID, "code": "GRP", "name": g.name, "source": "kiban", "isKibanManaged": true,
		}})
	})
	mux.HandleFunc("GET /internal/org/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		fo.mu.Lock()
		var out []map[string]any
		for memberID := range fo.groupMembers[r.PathValue("id")] {
			out = append(out, map[string]any{"groupId": r.PathValue("id"), "memberId": memberID})
		}
		fo.mu.Unlock()
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, map[string]any{"data": out})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	fo.url = srv.URL
	return fo
}

// ---- fake notification server -------------------------------------------------------------------

type fakeNotification struct {
	mu     sync.Mutex
	events []map[string]any
}

func newFakeNotification(t *testing.T) (*httptest.Server, *fakeNotification) {
	t.Helper()
	fn := &fakeNotification{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		fn.mu.Lock()
		fn.events = append(fn.events, body)
		fn.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{"sent": 1, "skipped": 0}})
	}))
	t.Cleanup(srv.Close)
	return srv, fn
}

// ---- fixture -------------------------------------------------------------------------------------

type httpFixture struct {
	svc     *Service
	handler http.Handler
	issuer  *testIssuer
	authz   *fakeAuthz
	org     *fakeOrg
	notif   *fakeNotification
}

func newHTTPFixture(t *testing.T, members map[string]bool, admins map[string]bool, orgMembers []fakeOrgMember) *httpFixture {
	t.Helper()
	return newHTTPFixtureWithPositions(t, members, admins, orgMembers, nil)
}

func newHTTPFixtureWithPositions(t *testing.T, members map[string]bool, admins map[string]bool, orgMembers []fakeOrgMember, positions []fakeOrgPosition) *httpFixture {
	t.Helper()
	return newHTTPFixtureWithPositionsAndGroups(t, members, admins, orgMembers, positions, nil)
}

// newHTTPFixtureWithGroups is the group sibling of
// newHTTPFixtureWithPositions.
func newHTTPFixtureWithGroups(t *testing.T, members map[string]bool, admins map[string]bool, orgMembers []fakeOrgMember, groups []fakeOrgGroup) *httpFixture {
	t.Helper()
	return newHTTPFixtureWithPositionsAndGroups(t, members, admins, orgMembers, nil, groups)
}

func newHTTPFixtureWithPositionsAndGroups(t *testing.T, members map[string]bool, admins map[string]bool, orgMembers []fakeOrgMember, positions []fakeOrgPosition, groups []fakeOrgGroup) *httpFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	fa := newFakeAuthz(members, admins)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, fa.server(t).URL)
	fo := newFakeOrgWithPositionsAndGroups(t, orgMembers, positions, groups)
	orgClient := NewOrgClient(&http.Client{Timeout: 5 * time.Second}, fo.url)
	notifSrv, fn := newFakeNotification(t)
	notifClient := NewNotificationClient(&http.Client{Timeout: 5 * time.Second}, notifSrv.URL)

	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient, notifClient)
	return &httpFixture{svc: svc, handler: svc.Routes(), issuer: issuer, authz: fa, org: fo, notif: fn}
}

// setPositionHolder is the combined double-mutator: keeps the authz fake's
// position->holder-kcSub fact AND the org fake's position->holder-memberID fact in sync in one
// call, mirroring the SAME single underlying fact org's own AssignNow would maintain in
// production (one assignment row, two independently-observed consequences: the tuple the engine
// walks, and the read org itself would answer "who holds this today").
func (f *httpFixture) setPositionHolder(positionID string, holder fakeOrgMember) {
	f.authz.setPositionHolder(positionID, holder.kcSub)
	f.org.setHolder(positionID, holder.id)
}

// clearPositionHolder is setPositionHolder's inverse.
func (f *httpFixture) clearPositionHolder(positionID string) {
	f.authz.clearPositionHolder(positionID)
	f.org.clearHolder(positionID)
}

// addGroupMember is setPositionHolder's group sibling: keeps the authz fake's
// group->member-kcSub-set fact AND the org fake's group->member-memberID-set fact in sync in one
// call, mirroring the SAME single underlying fact org's own AddGroupMember would maintain.
func (f *httpFixture) addGroupMember(groupID string, member fakeOrgMember) {
	f.authz.addGroupMember(groupID, member.kcSub)
	f.org.addGroupMember(groupID, member.id)
}

// removeGroupMember is addGroupMember's inverse.
func (f *httpFixture) removeGroupMember(groupID string, member fakeOrgMember) {
	f.authz.removeGroupMember(groupID, member.kcSub)
	f.org.removeGroupMember(groupID, member.id)
}

func (f *httpFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *httpFixture) do(t *testing.T, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doHeaders(t, method, path, bearer, body, nil)
}

// doHeaders is do plus arbitrary extra request headers (Idempotency-Key
// tests need to set a header do's own signature has no room for).
func (f *httpFixture) doHeaders(t *testing.T, method, path, bearer, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	// Every response this file's tests ever record is validated against
	// modules/helpdesk/openapi.yaml's declared schema for the operation the request matched —
	// status code and body shape both. Wired into the shared do/doHeaders helper so every
	// existing and future test gets the check "for free".
	if spec, err := testopenapi.LoadModule("helpdesk"); err != nil {
		t.Fatalf("testopenapi.LoadModule(helpdesk): %v", err)
	} else {
		spec.ValidateResponse(t, req, rec)
	}
	return rec
}

func decodeData(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		t.Fatalf("decode data: %v (body=%s)", err, rec.Body.String())
	}
}

// helpdeskErrEnvelope mirrors internal/errenv's error envelope shape — a local decode helper.
type helpdeskErrEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) helpdeskErrEnvelope {
	t.Helper()
	var e helpdeskErrEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, rec.Body.String())
	}
	return e
}

// ---- basic auth plumbing ---------------------------------------------------------------------

func TestHTTP_Health_NoAuthRequired(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MissingBearer_401(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	companyID := uuid.NewString()
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_NonMember_403_OnCreate(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{}, nil, nil)
	companyID := uuid.NewString()
	bearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", bearer, `{"title":"x","description":"y"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-member create, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---- the end-to-end workflow journey: reporter raises -> admin assigns to a non-agent (auto-grant)
// -> agent progresses/resolves -> reporter comments + reopens -> agent re-resolves -> reporter
// closes; tier contrast asserted throughout -------------------------------------------------------

func TestHTTP_FullWorkflowJourney(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice") // reporter
	bobBearer := f.token(t, "bob")     // future agent, not one yet
	adminBearer := f.token(t, "carol-admin")

	// 1. Alice (a plain member) raises a ticket.
	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"Printer on fire","description":"send help"}`)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	if ticket.Status != "open" {
		t.Fatalf("expected new ticket status=open, got %q", ticket.Status)
	}

	// 2. Bob (not yet an agent) cannot see view=all.
	allRecDenied := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets?view=all", bobBearer, "")
	if allRecDenied.Code != http.StatusForbidden {
		t.Fatalf("bob (non-agent) view=all: expected 403, got %d: %s", allRecDenied.Code, allRecDenied.Body.String())
	}

	// 3. Admin assigns the ticket to Bob — auto-grants the agent tier.
	assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer,
		fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))
	if assignRec.Code != http.StatusOK {
		t.Fatalf("assign: expected 200, got %d: %s", assignRec.Code, assignRec.Body.String())
	}
	if !f.authz.isAgent("bob") {
		t.Fatal("expected assignment to auto-grant bob the agent tier")
	}
	f.notif.mu.Lock()
	notifCountAfterAssign := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifCountAfterAssign != 1 {
		t.Fatalf("expected exactly 1 notification event after assignment, got %d", notifCountAfterAssign)
	}

	// 4. Bob, now an agent, CAN see view=all — the tier-contrast demo.
	allRecAllowed := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets?view=all", bobBearer, "")
	if allRecAllowed.Code != http.StatusOK {
		t.Fatalf("bob (agent) view=all: expected 200, got %d: %s", allRecAllowed.Code, allRecAllowed.Body.String())
	}

	// 5. Bob progresses the ticket open -> in_progress.
	progressRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"in_progress"}`)
	if progressRec.Code != http.StatusOK {
		t.Fatalf("progress: expected 200, got %d: %s", progressRec.Code, progressRec.Body.String())
	}

	// 6. Bob resolves it.
	resolveRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"resolved"}`)
	if resolveRec.Code != http.StatusOK {
		t.Fatalf("resolve: expected 200, got %d: %s", resolveRec.Code, resolveRec.Body.String())
	}

	// 7. Alice (the reporter) comments; this notifies Bob (the assignee).
	commentRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `{"body":"still smoking a little"}`)
	if commentRec.Code != http.StatusCreated {
		t.Fatalf("comment: expected 201, got %d: %s", commentRec.Code, commentRec.Body.String())
	}

	// 8. Alice reopens the resolved ticket.
	reopenRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"open"}`)
	if reopenRec.Code != http.StatusOK {
		t.Fatalf("reopen: expected 200, got %d: %s", reopenRec.Code, reopenRec.Body.String())
	}

	// 9. Bob progresses and resolves again.
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"in_progress"}`)
	reresolveRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"resolved"}`)
	if reresolveRec.Code != http.StatusOK {
		t.Fatalf("re-resolve: expected 200, got %d: %s", reresolveRec.Code, reresolveRec.Body.String())
	}

	// 10. Alice closes her own resolved ticket.
	closeRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"closed"}`)
	if closeRec.Code != http.StatusOK {
		t.Fatalf("close: expected 200, got %d: %s", closeRec.Code, closeRec.Body.String())
	}
	var closed ticketWire
	decodeData(t, closeRec, &closed)
	if closed.Status != "closed" {
		t.Fatalf("expected final status=closed, got %q", closed.Status)
	}
}

func TestHTTP_GetTicketAudit(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	adminBearer := f.token(t, "carol-admin")
	eveBearer := f.token(t, "eve") // not a member at all

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))

	auditRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/audit", aliceBearer, "")
	if auditRec.Code != http.StatusOK {
		t.Fatalf("audit: expected 200, got %d: %s", auditRec.Code, auditRec.Body.String())
	}
	var events []auditEventWire
	decodeData(t, auditRec, &events)
	if len(events) < 2 {
		t.Fatalf("expected at least 2 audit events (create, assign), got %d: %+v", len(events), events)
	}

	// A non-member cannot read the ticket's audit trail.
	deniedRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/audit", eveBearer, "")
	if deniedRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-member, got %d: %s", deniedRec.Code, deniedRec.Body.String())
	}
}

func TestHTTP_ReporterCannotSeeOthersTickets(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Eve", kcSub: "eve", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "eve": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	eveBearer := f.token(t, "eve")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"private","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	// Eve (a plain member, not the reporter, not an agent/admin) cannot read Alice's ticket.
	getRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID, eveBearer, "")
	if getRec.Code != http.StatusForbidden {
		t.Fatalf("eve get: expected 403, got %d: %s", getRec.Code, getRec.Body.String())
	}

	// Eve's own view=mine list is empty, never showing Alice's ticket.
	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets", eveBearer, "")
	var list []ticketWire
	decodeData(t, listRec, &list)
	if len(list) != 0 {
		t.Fatalf("expected eve's view=mine list empty, got %+v", list)
	}
}

func TestHTTP_NonAgent_403_OnViewAll(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets?view=all", aliceBearer, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_InvalidTransition_422(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	// open -> resolved directly is not a valid edge, even for an admin.
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", adminBearer, `{"status":"resolved"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for an invalid transition, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_TransitionDenied_403_NonAssigneeNonAdmin(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))

	// Alice (the reporter, not the assignee) cannot progress open -> in_progress.
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"in_progress"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for reporter progressing a ticket they don't own the work on, got %d: %s", rec.Code, rec.Body.String())
	}

	// Bob (the assignee) can.
	rec2 := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", bobBearer, `{"status":"in_progress"}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for the assignee, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestHTTP_AgentRemoval_ProtectionRule(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	adminBearer := f.token(t, "carol-admin")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"t","description":"d"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminBearer, fmt.Sprintf(`{"assigneeMemberId":%q}`, bobMemberID))

	// Bob is now an agent with an open assigned ticket — removal must be refused.
	removeRec := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/"+bobMemberID, adminBearer, "")
	if removeRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 (protection rule), got %d: %s", removeRec.Code, removeRec.Body.String())
	}
	if !f.authz.isAgent("bob") {
		t.Fatal("bob should still be an agent after a refused removal")
	}

	// Close the ticket, then removal succeeds.
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", f.token(t, "bob"), `{"status":"in_progress"}`)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", f.token(t, "bob"), `{"status":"resolved"}`)
	f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/status", aliceBearer, `{"status":"closed"}`)

	removeRec2 := f.do(t, http.MethodDelete, "/api/helpdesk/v1/companies/"+companyID+"/agents/"+bobMemberID, adminBearer, "")
	if removeRec2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 once the ticket is closed, got %d: %s", removeRec2.Code, removeRec2.Body.String())
	}
	if f.authz.isAgent("bob") {
		t.Fatal("bob should no longer be an agent after a successful removal")
	}
}

func TestHTTP_MakeAgent_ThenListAgents(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	adminBearer := f.token(t, "carol-admin")

	makeRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, fmt.Sprintf(`{"memberId":%q}`, bobMemberID))
	if makeRec.Code != http.StatusCreated {
		t.Fatalf("make agent: expected 201, got %d: %s", makeRec.Code, makeRec.Body.String())
	}

	listRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", adminBearer, "")
	var agents []agentWire
	decodeData(t, listRec, &agents)
	if len(agents) != 1 || agents[0].BindingKind != BindingKindMember || agents[0].MemberID == nil || *agents[0].MemberID != bobMemberID {
		t.Fatalf("expected exactly 1 member-bound agent matching bob, got %+v", agents)
	}
}

func TestHTTP_NonAdmin_403_OnMakeAgent(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/agents", aliceBearer, fmt.Sprintf(`{"memberId":%q}`, uuid.NewString()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MyTier(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, nil)
	aliceBearer := f.token(t, "alice")
	adminBearer := f.token(t, "carol-admin")

	aliceRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/me", aliceBearer, "")
	var aliceTier struct {
		Tier string `json:"tier"`
	}
	decodeData(t, aliceRec, &aliceTier)
	if aliceTier.Tier != "member" {
		t.Fatalf("expected alice tier=member, got %q", aliceTier.Tier)
	}

	adminRec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/me", adminBearer, "")
	var adminTier struct {
		Tier string `json:"tier"`
	}
	decodeData(t, adminRec, &adminTier)
	if adminTier.Tier != "admin" {
		t.Fatalf("expected admin tier=admin, got %q", adminTier.Tier)
	}
}

// TestHTTP_CreateTicket_IdempotencyKey_ReplayAndConflict proves idempotency for
// helpdesk's ticket-create write. Same key + same payload replays the
// FIRST ticket (200, unchanged, no new row). Same key + different payload is 409
// IDEMPOTENCY_CONFLICT. The same key reused by a DIFFERENT caller is scoped separately (a
// fresh ticket), never a cross-caller replay.
func TestHTTP_CreateTicket_IdempotencyKey_ReplayAndConflict(t *testing.T) {
	companyID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
		{id: uuid.NewString(), companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

	key := map[string]string{"Idempotency-Key": "helpdesk-ticket-key-1"}
	first := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"Printer on fire","description":"send help"}`, key)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d: %s", first.Code, first.Body.String())
	}
	var firstTicket ticketWire
	decodeData(t, first, &firstTicket)

	// same key, same payload -> replay (200, same ticket).
	replay := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"Printer on fire","description":"send help"}`, key)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}
	var replayTicket ticketWire
	decodeData(t, replay, &replayTicket)
	if replayTicket.ID != firstTicket.ID {
		t.Fatalf("replay returned a different ticket: %q, want %q", replayTicket.ID, firstTicket.ID)
	}

	// same key, different payload -> 409 IDEMPOTENCY_CONFLICT.
	conflict := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"DIFFERENT","description":"send help"}`, key)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: expected 409, got %d: %s", conflict.Code, conflict.Body.String())
	}
	if e := decodeErr(t, conflict); e.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error code = %q, want IDEMPOTENCY_CONFLICT", e.Error.Code)
	}

	// same key reused by a DIFFERENT caller (bob) -> scoped separately, a fresh ticket.
	bobRec := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", bobBearer, `{"title":"Printer on fire","description":"send help"}`, key)
	if bobRec.Code != http.StatusCreated {
		t.Fatalf("bob create with alice's key: expected 201 (scoped per caller), got %d: %s", bobRec.Code, bobRec.Body.String())
	}
	var bobTicket ticketWire
	decodeData(t, bobRec, &bobTicket)
	if bobTicket.ID == firstTicket.ID {
		t.Fatalf("bob's ticket should be distinct from alice's (key scoped per caller), got the same id %q", bobTicket.ID)
	}
}

// TestHTTP_CreateComment_IdempotencyKey_ReplayAndConflict is the comment-create
// counterpart: same key + same payload replays; same key + different payload is 409.
func TestHTTP_CreateComment_IdempotencyKey_ReplayAndConflict(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, []fakeOrgMember{
		{id: uuid.NewString(), companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true},
	})
	aliceBearer := f.token(t, "alice")

	createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", aliceBearer, `{"title":"T","description":"D"}`)
	var ticket ticketWire
	decodeData(t, createRec, &ticket)

	key := map[string]string{"Idempotency-Key": "helpdesk-comment-key-1"}
	first := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `{"body":"hello"}`, key)
	if first.Code != http.StatusCreated {
		t.Fatalf("first comment: expected 201, got %d: %s", first.Code, first.Body.String())
	}

	// same key, same payload -> replay (200).
	replay := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `{"body":"hello"}`, key)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}

	// same key, different body -> 409 IDEMPOTENCY_CONFLICT.
	conflict := f.doHeaders(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/comments", aliceBearer, `{"body":"DIFFERENT"}`, key)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: expected 409, got %d: %s", conflict.Code, conflict.Body.String())
	}
	if e := decodeErr(t, conflict); e.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error code = %q, want IDEMPOTENCY_CONFLICT", e.Error.Code)
	}
}

func TestHTTP_CreateTicket_InvalidCompanyID_400(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	bearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/not-a-uuid/tickets", bearer, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetTicket_NotFound_404(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	ticketID := uuid.NewString()
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticketID, aliceBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Ready(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/ready", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
