// SPDX-License-Identifier: Apache-2.0

package docs

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
// A real in-memory tuple store standing in for authz's own effective-access/grants surface (mocks
// only for genuinely external systems — authz is exactly that from this module's point of
// view). Implements enough of the REAL union semantics (owner -> editor -> viewer) for
// the tests below to exercise the actual grant/revoke/check round trip a real authz service would
// perform, including op:"revoke".

type fakeAuthz struct {
	mu      sync.Mutex
	tuples  map[string]bool // "objType:objID#relation@subjectId" -> true
	admins  map[string]bool // subs holding company_module#admin (docs.manage)
	members map[string]bool // subs that are active company members (docs.create + step 1-6 gate)
}

func newFakeAuthz(members map[string]bool, admins map[string]bool) *fakeAuthz {
	if admins == nil {
		admins = map[string]bool{}
	}
	return &fakeAuthz{tuples: map[string]bool{}, admins: admins, members: members}
}

func tupleKey(objType, objID, relation, subjectID string) string {
	return objType + ":" + objID + "#" + relation + "@" + subjectID
}

func (f *fakeAuthz) hasDirect(objType, objID, relation, subjectID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tuples[tupleKey(objType, objID, relation, subjectID)]
}

// hasRelation replicates docs_document's union rewrite: owner -> editor -> viewer.
func (f *fakeAuthz) hasRelation(docID, subjectID, relation string) bool {
	switch relation {
	case "owner":
		return f.hasDirect("docs_document", docID, "owner", subjectID)
	case "editor":
		return f.hasDirect("docs_document", docID, "editor", subjectID) || f.hasDirect("docs_document", docID, "owner", subjectID)
	case "viewer":
		return f.hasDirect("docs_document", docID, "viewer", subjectID) ||
			f.hasDirect("docs_document", docID, "editor", subjectID) ||
			f.hasDirect("docs_document", docID, "owner", subjectID)
	default:
		return false
	}
}

func (f *fakeAuthz) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/authz/effective-access/can", func(w http.ResponseWriter, r *http.Request) {
		sub := subjectFromBearer(r.Header.Get("Authorization"))
		var req struct {
			FeatureKey string `json:"featureKey"`
			Object     struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"object"`
			Relation string `json:"relation"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		var allowed bool
		var reason string
		switch {
		case req.Object.Type == "docs_document":
			allowed = f.hasRelation(req.Object.ID, "user:"+sub, req.Relation)
			reason = "ENGINE_DENIED"
			if allowed {
				reason = "ALLOWED"
			}
		case req.FeatureKey == featureDocsManage:
			allowed = f.admins[sub]
			reason = "COMPANY_MEMBERSHIP_REQUIRED"
			if allowed {
				reason = "ALLOWED"
			}
		default: // docs.create and any other feature-only check: membership only
			allowed = f.members[sub]
			reason = "COMPANY_MEMBERSHIP_REQUIRED"
			if allowed {
				reason = "ALLOWED"
			}
		}
		writeJSON(w, map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
	})
	mux.HandleFunc("POST /internal/authz/effective-access/batch-can", func(w http.ResponseWriter, r *http.Request) {
		sub := subjectFromBearer(r.Header.Get("Authorization"))
		var req struct {
			Items []struct {
				Object struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"object"`
				Relation string `json:"relation"`
			} `json:"items"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := make([]map[string]any, len(req.Items))
		for i, it := range req.Items {
			allowed := f.hasRelation(it.Object.ID, "user:"+sub, it.Relation)
			reason := "ENGINE_DENIED"
			if allowed {
				reason = "ALLOWED"
			}
			out[i] = map[string]any{
				"object":   map[string]string{"type": it.Object.Type, "id": it.Object.ID},
				"relation": it.Relation,
				"decision": map[string]any{"allowed": allowed, "reason": reason},
			}
		}
		writeJSON(w, map[string]any{"data": out})
	})
	mux.HandleFunc("POST /internal/authz/grants", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Op        string `json:"op"`
			CompanyID string `json:"companyId"`
			Tuples    []struct {
				ObjectType string `json:"objectType"`
				ObjectID   string `json:"objectId"`
				Relation   string `json:"relation"`
				SubjectID  string `json:"subjectId"`
			} `json:"tuples"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CompanyID == "" { // the real endpoint requires companyId
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		for _, tp := range req.Tuples {
			subject := "user:" + tp.SubjectID
			if tp.Relation == "company_module" {
				subject = "company_module:" + tp.SubjectID
			}
			key := tupleKey(tp.ObjectType, tp.ObjectID, tp.Relation, subject)
			if req.Op == "grant" {
				f.tuples[key] = true
			} else {
				delete(f.tuples, key)
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

func newFakeOrg(t *testing.T, members []fakeOrgMember) *httptest.Server {
	t.Helper()
	byID := map[string]fakeOrgMember{}
	byKcSub := map[string]fakeOrgMember{}
	for _, m := range members {
		byID[m.id] = m
		if m.kcSub != "" {
			byKcSub[m.kcSub] = m
		}
	}
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
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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
	notif   *fakeNotification
}

func newHTTPFixture(t *testing.T, members map[string]bool, admins map[string]bool, orgMembers []fakeOrgMember) *httpFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	fa := newFakeAuthz(members, admins)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, fa.server(t).URL)
	orgSrv := newFakeOrg(t, orgMembers)
	orgClient := NewOrgClient(&http.Client{Timeout: 5 * time.Second}, orgSrv.URL)
	notifSrv, fn := newFakeNotification(t)
	notifClient := NewNotificationClient(&http.Client{Timeout: 5 * time.Second}, notifSrv.URL)

	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient, notifClient)
	return &httpFixture{svc: svc, handler: svc.Routes(), issuer: issuer, authz: fa, notif: fn}
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
	// modules/docs/openapi.yaml's declared schema for the operation the request matched — status
	// code and body shape both. Wired into the shared do/doHeaders helper (rather than added
	// call-by-call) so every existing and future test in this package gets the check "for free":
	// happy paths AND the many already-covered error paths (400/401/403/404/409/422) alike.
	if spec, err := testopenapi.LoadModule("docs"); err != nil {
		t.Fatalf("testopenapi.LoadModule(docs): %v", err)
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

// docsErrEnvelope mirrors internal/errenv's error envelope shape ({"error":{"code",...}}) — a
// local decode helper.
type docsErrEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeDocsErr(t *testing.T, rec *httptest.ResponseRecorder) docsErrEnvelope {
	t.Helper()
	var e docsErrEnvelope
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
	rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_NonMember_403_OnCreate(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{}, nil, nil)
	companyID := uuid.NewString()
	bearer := f.token(t, "alice")
	rec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", bearer, `{"title":"x","body":"y"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-member create, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---- the end-to-end sharing journey: create -> share viewer -> second identity reads but cannot
// edit -> upgrade to editor -> edits -> revoke -> second identity loses access -> audit shows it
// all -> admin cannot read content -----------------------------------------------------------

func TestHTTP_FullSharingJourney(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true, "carol-admin": true}, map[string]bool{"carol-admin": true}, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")
	adminBearer := f.token(t, "carol-admin")

	// 1. Alice creates a document — she is its owner.
	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"Runbook","body":"secret content"}`)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var doc documentWire
	decodeData(t, createRec, &doc)
	if doc.MyRelation != "owner" {
		t.Fatalf("expected myRelation=owner, got %q", doc.MyRelation)
	}

	// 2. Bob cannot read it yet — ungranted, unreadable (the excludability property).
	getRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, "")
	if getRec.Code != http.StatusForbidden {
		t.Fatalf("bob pre-share get: expected 403, got %d: %s", getRec.Code, getRec.Body.String())
	}

	// 3. Alice shares it with Bob as viewer.
	shareRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, bobMemberID))
	if shareRec.Code != http.StatusCreated {
		t.Fatalf("share: expected 201, got %d: %s", shareRec.Code, shareRec.Body.String())
	}
	f.notif.mu.Lock()
	notifCountAfterShare := len(f.notif.events)
	f.notif.mu.Unlock()
	if notifCountAfterShare != 1 {
		t.Fatalf("expected exactly 1 notification event after sharing, got %d", notifCountAfterShare)
	}

	// 4. Bob can now read it, but PUT (editor) is still denied.
	getRec2 := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, "")
	if getRec2.Code != http.StatusOK {
		t.Fatalf("bob post-share get: expected 200, got %d: %s", getRec2.Code, getRec2.Body.String())
	}
	var bobView documentWire
	decodeData(t, getRec2, &bobView)
	if bobView.MyRelation != "viewer" {
		t.Fatalf("expected bob's myRelation=viewer, got %q", bobView.MyRelation)
	}
	putRec := f.do(t, http.MethodPut, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, `{"title":"Runbook","body":"bob's edit"}`)
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("bob viewer-only put: expected 403, got %d: %s", putRec.Code, putRec.Body.String())
	}

	// 5. Alice upgrades Bob to editor.
	upgradeRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"editor"}`, bobMemberID))
	if upgradeRec.Code != http.StatusCreated {
		t.Fatalf("upgrade share: expected 201, got %d: %s", upgradeRec.Code, upgradeRec.Body.String())
	}

	// 6. Bob can now edit.
	putRec2 := f.do(t, http.MethodPut, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, `{"title":"Runbook v2","body":"bob's edit"}`)
	if putRec2.Code != http.StatusOK {
		t.Fatalf("bob editor put: expected 200, got %d: %s", putRec2.Code, putRec2.Body.String())
	}

	// 7. Alice revokes Bob's access entirely.
	revokeRec := f.do(t, http.MethodDelete, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares/"+bobMemberID, aliceBearer, "")
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d: %s", revokeRec.Code, revokeRec.Body.String())
	}

	// 8. Bob loses access entirely — 403 again (revoke:"op" actually worked, not just a local
	// index delete — engine truth, not the index, decides this).
	getRec3 := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, "")
	if getRec3.Code != http.StatusForbidden {
		t.Fatalf("bob post-revoke get: expected 403, got %d: %s", getRec3.Code, getRec3.Body.String())
	}

	// 9. The document's own audit trail shows create + 2 shares + revoke + 1 edit.
	auditRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/audit", aliceBearer, "")
	if auditRec.Code != http.StatusOK {
		t.Fatalf("doc audit: expected 200, got %d: %s", auditRec.Code, auditRec.Body.String())
	}
	var events []auditEventWire
	decodeData(t, auditRec, &events)
	if len(events) < 5 {
		t.Fatalf("expected at least 5 audit events (create, share x2, edit, revoke), got %d: %+v", len(events), events)
	}

	// 10. The platform superadmin / docs.manage admin still cannot read the document content —
	// docs.manage authorizes the MODULE audit view only, never document content (the
	// excludability demo's other half). The admin never even attempted a GET here (no relation
	// leg exists for docs.manage on docs_document), but the module audit view IS reachable and
	// never carries body content.
	moduleAuditRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/audit", adminBearer, "")
	if moduleAuditRec.Code != http.StatusOK {
		t.Fatalf("module audit: expected 200, got %d: %s", moduleAuditRec.Code, moduleAuditRec.Body.String())
	}
	if strings.Contains(moduleAuditRec.Body.String(), "secret content") || strings.Contains(moduleAuditRec.Body.String(), "bob's edit") {
		t.Fatalf("module audit trail leaked document body content: %s", moduleAuditRec.Body.String())
	}
	adminDocGetRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, adminBearer, "")
	if adminDocGetRec.Code != http.StatusForbidden {
		t.Fatalf("admin (docs.manage only, no per-doc grant) get: expected 403 (superadmin excludability), got %d: %s", adminDocGetRec.Code, adminDocGetRec.Body.String())
	}
}

func TestHTTP_DeleteDocument_OwnerOnly(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)

	f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"editor"}`, bobMemberID))

	// Bob is an editor, not the owner — delete must be denied.
	delRec := f.do(t, http.MethodDelete, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, bobBearer, "")
	if delRec.Code != http.StatusForbidden {
		t.Fatalf("editor delete: expected 403, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// The owner can delete.
	delRec2 := f.do(t, http.MethodDelete, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID, aliceBearer, "")
	if delRec2.Code != http.StatusNoContent {
		t.Fatalf("owner delete: expected 204, got %d: %s", delRec2.Code, delRec2.Body.String())
	}
}

func TestHTTP_OwnerCannotRevokeSelf(t *testing.T) {
	companyID := uuid.NewString()
	aliceMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: aliceMemberID, companyID: companyID, displayName: "Alice", kcSub: "alice", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)

	rec := f.do(t, http.MethodDelete, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares/"+aliceMemberID, aliceBearer, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("owner self-revoke: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateDocument_IdempotencyKey_ReplayAndConflict proves idempotency for
// docs's document-create write. Same key + same payload replays the
// FIRST document (200, unchanged) — a SECOND owner-grant round trip never happens (proven
// indirectly: the replay must not fail even though a repeat GrantDocumentOwner with the SAME
// docID would 500 with a duplicate-tuple style failure had the handler granted again). Same key
// + different payload is 409 IDEMPOTENCY_CONFLICT.
func TestHTTP_CreateDocument_IdempotencyKey_ReplayAndConflict(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, map[string]bool{}, nil)
	aliceBearer := f.token(t, "alice")

	key := map[string]string{"Idempotency-Key": "docs-create-key-1"}
	first := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"Runbook","body":"v1"}`, key)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d: %s", first.Code, first.Body.String())
	}
	var firstDoc documentWire
	decodeData(t, first, &firstDoc)

	// same key, same payload -> replay (200, same document, no new grant).
	replay := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"Runbook","body":"v1"}`, key)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}
	var replayDoc documentWire
	decodeData(t, replay, &replayDoc)
	if replayDoc.ID != firstDoc.ID {
		t.Fatalf("replay returned a different document: %q, want %q", replayDoc.ID, firstDoc.ID)
	}

	// same key, different payload -> 409 IDEMPOTENCY_CONFLICT, never a silent replay.
	conflict := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"Runbook","body":"DIFFERENT"}`, key)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: expected 409, got %d: %s", conflict.Code, conflict.Body.String())
	}
	if e := decodeDocsErr(t, conflict); e.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error code = %q, want IDEMPOTENCY_CONFLICT", e.Error.Code)
	}

	// same key reused by a DIFFERENT caller (different owner_kcsub) -> scoped separately, a
	// fresh create, never treated as a replay of alice's document.
	f2 := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, map[string]bool{}, nil)
	company2 := uuid.NewString()
	aliceBearer2 := f2.token(t, "alice")
	bobBearer2 := f2.token(t, "bob")

	aRec := f2.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+company2+"/documents", aliceBearer2, `{"title":"Scoped","body":"a"}`, key)
	if aRec.Code != http.StatusCreated {
		t.Fatalf("alice create in scope test: expected 201, got %d: %s", aRec.Code, aRec.Body.String())
	}
	bRec := f2.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+company2+"/documents", bobBearer2, `{"title":"Scoped","body":"a"}`, key)
	if bRec.Code != http.StatusCreated {
		t.Fatalf("bob create with the SAME key as alice's: expected 201 (scoped per caller, not shared), got %d: %s", bRec.Code, bRec.Body.String())
	}
	var aDoc, bDoc documentWire
	decodeData(t, aRec, &aDoc)
	decodeData(t, bRec, &bDoc)
	if aDoc.ID == bDoc.ID {
		t.Fatalf("alice's and bob's documents should be distinct (key scoped per caller), got the same id %q", aDoc.ID)
	}
}

// TestHTTP_CreateShare_IdempotencyKey_ReplayAndConflict is the share-create
// counterpart: same key + same payload replays; same key + different payload (a different
// relation) is 409.
func TestHTTP_CreateShare_IdempotencyKey_ReplayAndConflict(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{
		{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true},
	}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, map[string]bool{}, orgMembers)
	aliceBearer := f.token(t, "alice")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)

	key := map[string]string{"Idempotency-Key": "docs-share-key-1"}
	first := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, bobMemberID), key)
	if first.Code != http.StatusCreated {
		t.Fatalf("first share: expected 201, got %d: %s", first.Code, first.Body.String())
	}

	// same key, same payload -> replay (200).
	replay := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, bobMemberID), key)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}

	// same key, different relation -> 409 IDEMPOTENCY_CONFLICT.
	conflict := f.doHeaders(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"editor"}`, bobMemberID), key)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: expected 409, got %d: %s", conflict.Code, conflict.Body.String())
	}
	if e := decodeDocsErr(t, conflict); e.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error code = %q, want IDEMPOTENCY_CONFLICT", e.Error.Code)
	}
}

func TestHTTP_ShareWithMemberWithoutLinkedUser_422(t *testing.T) {
	companyID := uuid.NewString()
	noUserMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: noUserMemberID, companyID: companyID, displayName: "NoUser", kcSub: "", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)

	rec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, noUserMemberID))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("share with no linked user: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_ListDocuments_OwnedAndShared(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")
	bobBearer := f.token(t, "bob")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)
	f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, bobMemberID))

	listRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents", bobBearer, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var out struct {
		Owned        []documentWire `json:"owned"`
		SharedWithMe []documentWire `json:"sharedWithMe"`
	}
	decodeData(t, listRec, &out)
	if len(out.Owned) != 0 {
		t.Fatalf("bob owns nothing, got %d owned", len(out.Owned))
	}
	if len(out.SharedWithMe) != 1 || out.SharedWithMe[0].ID != doc.ID {
		t.Fatalf("expected exactly 1 shared-with-me doc matching %s, got %+v", doc.ID, out.SharedWithMe)
	}

	aliceListRec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, "")
	var aliceOut struct {
		Owned        []documentWire `json:"owned"`
		SharedWithMe []documentWire `json:"sharedWithMe"`
	}
	decodeData(t, aliceListRec, &aliceOut)
	if len(aliceOut.Owned) != 1 || aliceOut.Owned[0].ID != doc.ID {
		t.Fatalf("expected alice to own exactly 1 doc matching %s, got %+v", doc.ID, aliceOut.Owned)
	}
}

func TestHTTP_ListShares(t *testing.T) {
	companyID := uuid.NewString()
	bobMemberID := uuid.NewString()
	orgMembers := []fakeOrgMember{{id: bobMemberID, companyID: companyID, displayName: "Bob", kcSub: "bob", isActive: true}}
	f := newHTTPFixture(t, map[string]bool{"alice": true, "bob": true}, nil, orgMembers)
	aliceBearer := f.token(t, "alice")

	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)
	f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"viewer"}`, bobMemberID))

	rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list shares: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var shares []shareWire
	decodeData(t, rec, &shares)
	if len(shares) != 1 || shares[0].MemberID != bobMemberID {
		t.Fatalf("expected exactly 1 share for bob, got %+v", shares)
	}
}

func TestHTTP_CreateShare_InvalidRelation_400(t *testing.T) {
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	aliceBearer := f.token(t, "alice")
	createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", aliceBearer, `{"title":"D","body":"b"}`)
	var doc documentWire
	decodeData(t, createRec, &doc)

	rec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", aliceBearer,
		fmt.Sprintf(`{"memberId":%q,"relation":"admin"}`, uuid.NewString()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid relation: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetDocument_NotFound_404(t *testing.T) {
	// A caller who somehow holds a viewer tuple on an id with no row (shouldn't happen in
	// practice, but the store layer must still answer 404 rather than a panic/500).
	companyID := uuid.NewString()
	f := newHTTPFixture(t, map[string]bool{"alice": true}, nil, nil)
	docID := uuid.NewString()
	f.authz.mu.Lock()
	f.authz.tuples[tupleKey("docs_document", docID, "viewer", "user:alice")] = true
	f.authz.mu.Unlock()
	aliceBearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+docID, aliceBearer, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_InvalidCompanyID_400(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	bearer := f.token(t, "alice")
	rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/not-a-uuid/documents", bearer, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Ready(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/ready", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
