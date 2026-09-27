// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// httpTestFixture bundles a Service wired to real DB fixtures for http_test.go — same pattern as
// internal/identity/http_test.go's fixture.
type httpTestFixture struct {
	svc *Service
}

func newHTTPTestFixture(t *testing.T) *httpTestFixture {
	t.Helper()
	admin := adminPool(t)
	resetOrgFixtures(t, admin)

	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	store := NewStore(orgPool(t), auditWriter)
	identity := &fakeIdentityChecker{exists: map[string]bool{}}

	svc := NewService(store, identity, NewDenyAllAuthorizer(), auditWriter)
	return &httpTestFixture{svc: svc}
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body not valid JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

// TestHTTP_CreateUnit_FailClosed503AndAudited proves fail-closed behaviour: the v1
// denyAllAuthorizer refuses every mutation with 503, and the denial is itself audited.
func TestHTTP_CreateUnit_FailClosed503AndAudited(t *testing.T) {
	f := newHTTPTestFixture(t)
	admin := adminPool(t)

	body := `{"typeKey":"company","code":"HTTPCO","name":"HTTP Co"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/org/units", strings.NewReader(body))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	envelope := decodeEnvelope(t, rec)
	errObj := envelope["error"].(map[string]any)
	if errObj["code"] != "AUTHORIZATION_UNAVAILABLE" {
		t.Errorf("code = %v, want AUTHORIZATION_UNAVAILABLE", errObj["code"])
	}

	var count int
	err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.org__events
		WHERE subject = 'org_unit:new' AND action = 'org.unit.create' AND payload->>'denied' = 'true'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 denial audit row, got %d", count)
	}

	// Fail-closed: no unit was actually created.
	var unitCount int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM org.org_unit WHERE code = 'HTTPCO'`).Scan(&unitCount); err != nil {
		t.Fatalf("count units: %v", err)
	}
	if unitCount != 0 {
		t.Fatalf("unit was created despite the 503 fail-closed guard")
	}
}

// TestHTTP_GetUnit_Success proves reads are open (no AdminAuthorizer gate on GETs).
func TestHTTP_GetUnit_Success(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "HTTPCO2")

	req := httptest.NewRequest(http.MethodGet, "/internal/org/units/"+company.ID.String(), nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	envelope := decodeEnvelope(t, rec)
	data := envelope["data"].(map[string]any)
	if data["code"] != "HTTPCO2" {
		t.Fatalf("unexpected unit: %v", data)
	}
}

// TestHTTP_Subtree_Success proves the subtree endpoint (facts-only read, no auth gate).
func TestHTTP_Subtree_Success(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "HTTPCO3")
	mustCreateUnit(t, f.svc.store, "territory", company.ID, "HTTPTR")

	req := httptest.NewRequest(http.MethodGet, "/internal/org/units/"+company.ID.String()+"/subtree", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	envelope := decodeEnvelope(t, rec)
	items := envelope["data"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected 2 units in subtree, got %d: %v", len(items), items)
	}
}

// TestHTTP_ListMembers_Pagination proves the member directory list endpoint returns the
// standard page envelope shape.
func TestHTTP_ListMembers_Pagination(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "HTTPCO4")
	mustCreateMember(t, f.svc.store, company.ID, "HM1")
	mustCreateMember(t, f.svc.store, company.ID, "HM2")

	// handleListMembers is gated (requireMemberOrAdmin) — the caller
	// must name itself (kcSub) and be an active member. Link one of the two members created
	// above to a real identity user so this request self-authorizes.
	admin := adminPool(t)
	mustCreateIdentityUser(t, admin, "http-list-members-kcsub")
	member1, err := f.svc.store.GetMember(context.Background(), mustFirstMemberID(t, f.svc.store, company.ID))
	if err != nil {
		t.Fatalf("get member: %v", err)
	}
	if _, err := f.svc.store.LinkUser(context.Background(), "test-actor", &fakeIdentityChecker{exists: map[string]bool{"http-list-members-kcsub": true}}, member1.ID, "http-list-members-kcsub"); err != nil {
		t.Fatalf("link user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/org/members?companyId="+company.ID.String()+"&kcSub=http-list-members-kcsub", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	envelope := decodeEnvelope(t, rec)
	data := envelope["data"].(map[string]any)
	if data["total"].(float64) != 2 {
		t.Fatalf("expected total=2, got %v", data["total"])
	}
	if data["page"].(float64) != 1 || data["pageSize"].(float64) != 25 {
		t.Fatalf("unexpected pagination defaults: %v", data)
	}
}

// TestHTTP_ListMembers_UngatedCallerRejected proves a caller that doesn't name itself (no kcSub)
// or isn't an active member/admin is refused.
func TestHTTP_ListMembers_UngatedCallerRejected(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "HTTPCO4B")

	t.Run("missing kcSub: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/members?companyId="+company.ID.String(), nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("kcSub not a member, no admin bearer: 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/members?companyId="+company.ID.String()+"&kcSub=nobody-here", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// mustFirstMemberID returns the id of some member of companyID — a small helper for tests that
// only need "a member of this company exists," not which one.
func mustFirstMemberID(t *testing.T, store *Store, companyID uuid.UUID) uuid.UUID {
	t.Helper()
	members, _, err := store.ListMembers(context.Background(), companyID, 1, 1)
	if err != nil || len(members) == 0 {
		t.Fatalf("expected at least one member of company %s: members=%v err=%v", companyID, members, err)
	}
	return members[0].ID
}

// TestHTTP_HealthAndReady proves both endpoints are open and DB-backed as designed.
func TestHTTP_HealthAndReady(t *testing.T) {
	f := newHTTPTestFixture(t)
	for _, path := range []string{"/health", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200, body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

// TestHTTP_CreateAndAssign_FailClosed503 proves the combined create+assign endpoint is guarded
// the same as every other mutation.
func TestHTTP_CreateAndAssign_FailClosed503(t *testing.T) {
	f := newHTTPTestFixture(t)
	body := `{"companyId":"00000000-0000-0000-0000-000000000000","code":"X","title":"X","orgUnitId":"00000000-0000-0000-0000-000000000000","memberId":"00000000-0000-0000-0000-000000000000","validFrom":"2026-01-01"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/org/positions:create-and-assign", strings.NewReader(body))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}
