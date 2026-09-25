// SPDX-License-Identifier: Apache-2.0

package timesheet

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

// fakeOrg is a minimal stand-in for org's internal member-facts endpoints (modules consume
// facts through APIs only) — an httptest server, not a mock of this package's own code (mocks
// only for genuinely external systems; org is exactly that from this module's point of view).
// Mirrors modules/notification/service/http_test.go's newFakeAuthz shape.
type fakeMember struct {
	CompanyID string
	KcSub     string
	IsActive  bool
}

func newFakeOrg(t *testing.T, members map[string]fakeMember) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/members/by-kcsub/"):
			parts := strings.Split(r.URL.Path, "/")
			kcSub := parts[len(parts)-1]
			for id, m := range members {
				if m.KcSub == kcSub {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": m.IsActive, "memberId": id}})
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": false, "isActive": false, "memberId": nil}})
		case strings.HasPrefix(r.URL.Path, "/internal/org/members/"):
			id := strings.TrimPrefix(r.URL.Path, "/internal/org/members/")
			m, ok := members[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": id, "companyId": m.CompanyID, "displayName": "Test Member", "isActive": m.IsActive,
				"user": map[string]any{"kcSub": m.KcSub},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeAuthz is a minimal stand-in for authz's effective-access/grants endpoints. Grants issued
// through it actually mutate its own relation set, so a test can exercise the real
// handleAssignApprover -> AuthzClient.GrantRelation -> subsequent submit/approve authorization
// path end to end, same as the live authz service would.
type fakeAuthz struct {
	mu        sync.Mutex
	relations map[string]map[string]bool // relation -> kcSub -> granted
	members   map[string]bool            // kcSub -> is company member (membership-only features)
}

func newFakeAuthz(t *testing.T, members map[string]bool, admins map[string]bool) *httptest.Server {
	t.Helper()
	fa := &fakeAuthz{relations: map[string]map[string]bool{"admin": admins, "submitter": {}, "approver": {}}, members: members}
	if fa.relations["admin"] == nil {
		fa.relations["admin"] = map[string]bool{}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/authz/effective-access/can":
			var req authzCanRequestWire
			_ = json.NewDecoder(r.Body).Decode(&req)
			sub := subjectFromBearer(r.Header.Get("Authorization"))
			fa.mu.Lock()
			var allowed bool
			if req.Relation == "" {
				allowed = fa.members[sub]
			} else {
				allowed = fa.relations[req.Relation][sub]
			}
			fa.mu.Unlock()
			reason := "DENIED"
			if allowed {
				reason = "ALLOWED"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
		case "/internal/authz/grants":
			var req grantsRequestWire
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.CompanyID == "" { // the real endpoint requires companyId
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fa.mu.Lock()
			for _, tup := range req.Tuples {
				if fa.relations[tup.Relation] == nil {
					fa.relations[tup.Relation] = map[string]bool{}
				}
				fa.relations[tup.Relation][tup.SubjectID] = req.Op == "grant"
			}
			fa.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "ok"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
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

type httpFixture struct {
	handler http.Handler
	issuer  *testIssuer
}

func newHTTPFixture(t *testing.T, members map[string]fakeMember, companyMembers, admins map[string]bool) *httpFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	orgSrv := newFakeOrg(t, members)
	authzSrv := newFakeAuthz(t, companyMembers, admins)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, authzSrv.URL)
	orgClient := NewOrgClient(&http.Client{Timeout: 5 * time.Second}, orgSrv.URL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient)
	return &httpFixture{handler: svc.Routes(), issuer: issuer}
}

func (f *httpFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *httpFixture) do(t *testing.T, method, path, bearer, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	// Every response this file's tests ever record is validated against
	// modules/timesheet/openapi.yaml's declared schema for the operation the request matched —
	// status code and body shape both.
	if spec, err := testopenapi.LoadModule("timesheet"); err != nil {
		t.Fatalf("testopenapi.LoadModule(timesheet): %v", err)
	} else {
		spec.ValidateResponse(t, req, rec)
	}
	return rec
}

func TestHTTP_Health_NoAuthRequired(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	rec := f.do(t, http.MethodGet, "/health", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MissingBearer_401(t *testing.T) {
	f := newHTTPFixture(t, nil, nil, nil)
	companyID := uuid.New().String()
	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", "", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_NonMember_403(t *testing.T) {
	companyID := uuid.New().String()
	f := newHTTPFixture(t, nil, map[string]bool{}, nil)
	tok := f.token(t, "kcsub-outsider")
	rec := f.do(t, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", tok, "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_FullJourney is the module's end-to-end journey, at the HTTP layer, against fakes for
// org/authz (real Postgres via newTestStore): admin assigns approver -> member enters hours ->
// submits -> approver rejects w/ reason -> member edits+resubmits -> approver approves ->
// superseded version cannot be approved.
func TestHTTP_FullJourney(t *testing.T) {
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
	memberTok := f.token(t, memberSub)
	approverTok := f.token(t, approverSub)

	// admin creates a project.
	rec := f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", adminTok,
		`{"code":"PRJ1","name":"Project One"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", rec.Code, rec.Body.String())
	}
	var projResp struct {
		Data struct{ ID string } `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &projResp)

	// admin assigns approver for member (grants submitter+approver relations via authz).
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/approvers", adminTok,
		fmt.Sprintf(`{"memberId":%q,"approverMemberId":%q}`, memberID, approverID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign approver: %d %s", rec.Code, rec.Body.String())
	}

	week := isoMonday(time.Now().UTC()).Format("2006-01-02")

	// member enters hours.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
		fmt.Sprintf(`{"projectId":%q,"entryDate":%q,"realHours":8,"billableHours":6}`, projResp.Data.ID, week), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert entry: %d %s", rec.Code, rec.Body.String())
	}

	// member submits.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok,
		fmt.Sprintf(`{"weekStart":%q}`, week), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	var subResp struct {
		Data struct {
			ID         string `json:"id"`
			IsCurrent  bool   `json:"isCurrent"`
			Status     string `json:"status"`
			VersionNum int    `json:"versionNumber"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &subResp)
	v1ID := subResp.Data.ID
	if subResp.Data.Status != "submitted" || subResp.Data.VersionNum != 1 {
		t.Fatalf("v1 = %+v", subResp.Data)
	}

	// member cannot approve/reject their own submission (not the assigned approver).
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+v1ID+"/approve", memberTok, "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member self-approve: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// approver rejects with a reason.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+v1ID+"/reject", approverTok,
		`{"reason":"wrong hours"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}

	// reject without a reason is rejected (422) — separately, on a fresh submission cycle
	// this would 422 before ever reaching "not submitted"; already proven at the store layer
	// (TestStore_SubmissionLifecycle) so not re-asserted here at the HTTP layer.

	// member edits (entries reverted to draft by the reject) and resubmits -> v2.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/entries", memberTok,
		fmt.Sprintf(`{"projectId":%q,"entryDate":%q,"realHours":8,"billableHours":7}`, projResp.Data.ID, week), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-upsert entry: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions", memberTok,
		fmt.Sprintf(`{"weekStart":%q}`, week), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("resubmit: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &subResp)
	v2ID := subResp.Data.ID
	if subResp.Data.VersionNum != 2 {
		t.Fatalf("v2 = %+v", subResp.Data)
	}

	// the superseded v1 can never be approved.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+v1ID+"/approve", approverTok, "", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("approve superseded v1: expected 422, got %d: %s", rec.Code, rec.Body.String())
	}

	// approver approves v2.
	rec = f.do(t, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/submissions/"+v2ID+"/approve", approverTok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve v2: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &subResp)
	if subResp.Data.Status != "approved" {
		t.Fatalf("v2 final status = %+v", subResp.Data)
	}
}
