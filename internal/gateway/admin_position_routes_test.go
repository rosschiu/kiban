// SPDX-License-Identifier: Apache-2.0

// Negative matrix for `/api/org/admin/*` — every
// route behind the superadmin guard: missing bearer 401, non-superadmin 403, authz outage
// 503 (fail-closed), forged x-user-* rejected, and (allowed) forwards verbatim to org with the
// company/position path segment preserved. Body-ID-mismatch 422 and audit-actor coverage live in
// internal/org/http_more_test.go (org's own handler owns that validation — this file proves the
// gateway forwards the request/response faithfully, not that org validates it, matching
// foundation_routes_test.go's own division of labor).
package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newAdminPositionTestFixture(t *testing.T, adminClient *AuthzAdminClient) *foundationTestFixture {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	mux := http.NewServeMux()
	mountAdminPositionRoutes(mux, verifier, nil, target, adminClient)
	return &foundationTestFixture{t: t, jwks: jwks, backend: backend, mux: mux}
}

func allowedAdminClient(t *testing.T) *AuthzAdminClient {
	t.Helper()
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	t.Cleanup(srv.Close)
	return NewAuthzAdminClient(srv.URL)
}

func deniedAdminClient(t *testing.T) *AuthzAdminClient {
	t.Helper()
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":false,"reason":"PLATFORM_ROLE_REQUIRED","evidence":[]}}`)
	t.Cleanup(srv.Close)
	return NewAuthzAdminClient(srv.URL)
}

var adminPositionRoutes = []struct {
	name   string
	method string
	path   string
	body   string
}{
	{"list", http.MethodGet, "/api/org/admin/companies/co-1/positions", ""},
	{"create", http.MethodPost, "/api/org/admin/companies/co-1/positions", `{"code":"cfo","title":"CFO"}`},
	{"assign", http.MethodPost, "/api/org/admin/positions/pos-1/assignments", `{"memberId":"mem-1"}`},
	{"end", http.MethodPost, "/api/org/admin/assignments/asg-1/end", ``},
}

func TestAdminPositionRoutes_MissingBearer_401(t *testing.T) {
	for _, rt := range adminPositionRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminPositionTestFixture(t, allowedAdminClient(t))
			rec := doFoundationRequest(t, f.mux, rt.method, rt.path, "", rt.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 with no bearer, body=%s", rec.Code, rec.Body.String())
			}
			if len(f.backend.calls) != 0 {
				t.Fatalf("backend must never be called without a bearer, got %d calls", len(f.backend.calls))
			}
		})
	}
}

func TestAdminPositionRoutes_NonSuperadmin_403(t *testing.T) {
	for _, rt := range adminPositionRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminPositionTestFixture(t, deniedAdminClient(t))
			bearer := f.bearerFor("regular-user")
			rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for a non-superadmin bearer, body=%s", rec.Code, rec.Body.String())
			}
			if len(f.backend.calls) != 0 {
				t.Fatalf("org backend must never be called when the guard denies, got %d calls", len(f.backend.calls))
			}
		})
	}
}

func TestAdminPositionRoutes_AuthzOutage_503FailClosed(t *testing.T) {
	unreachable := NewAuthzAdminClient("http://127.0.0.1:1")
	for _, rt := range adminPositionRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminPositionTestFixture(t, unreachable)
			bearer := f.bearerFor("someone")
			rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (fail-closed on guard uncertainty), body=%s", rec.Code, rec.Body.String())
			}
			if len(f.backend.calls) != 0 {
				t.Fatalf("org backend must never be called when the guard is uncertain, got %d calls", len(f.backend.calls))
			}
		})
	}
}

func TestAdminPositionRoutes_ForgedUserHeader_Rejected400(t *testing.T) {
	for _, rt := range adminPositionRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminPositionTestFixture(t, allowedAdminClient(t))
			bearer := f.bearerFor("superadmin")

			var bodyReader *strings.Reader
			if rt.body != "" {
				bodyReader = strings.NewReader(rt.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(rt.method, rt.path, bodyReader)
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("X-User-Id", "spoofed-superadmin")
			rec := httptest.NewRecorder()
			f.mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for a forged x-user-* header, body=%s", rec.Code, rec.Body.String())
			}
			if len(f.backend.calls) != 0 {
				t.Fatalf("org backend must never be called when a forged x-user-* header is present, got %d calls", len(f.backend.calls))
			}
		})
	}
}

func TestAdminPositionRoutes_Allowed_ForwardsToOrgWithPathPreserved(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		body         string
		wantFwdPath  string
		responsePath string
	}{
		{"list", http.MethodGet, "/api/org/admin/companies/co-1/positions", "", "/internal/org/companies/co-1/positions", "/internal/org/companies/co-1/positions"},
		{"create", http.MethodPost, "/api/org/admin/companies/co-1/positions", `{"code":"cfo","title":"CFO"}`, "/internal/org/companies/co-1/positions", "/internal/org/companies/co-1/positions"},
		{"assign", http.MethodPost, "/api/org/admin/positions/pos-1/assignments", `{"memberId":"mem-1"}`, "/internal/org/positions/pos-1/assignments", "/internal/org/positions/pos-1/assignments"},
		{"end", http.MethodPost, "/api/org/admin/assignments/asg-1/end", ``, "/internal/org/assignments/asg-1/end", "/internal/org/assignments/asg-1/end"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdminPositionTestFixture(t, allowedAdminClient(t))
			f.backend.setResponse(tc.responsePath, http.StatusOK, `{"data":{"ok":true}}`)
			bearer := f.bearerFor("superadmin")

			rec := doFoundationRequest(t, f.mux, tc.method, tc.path, bearer, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 relayed from org, body=%s", rec.Code, rec.Body.String())
			}
			call := f.backend.lastCall()
			if call.path != tc.wantFwdPath {
				t.Errorf("forwarded path = %q, want %q", call.path, tc.wantFwdPath)
			}
			if call.authValue != "Bearer "+bearer {
				t.Errorf("Authorization not forwarded verbatim to org: got %q", call.authValue)
			}
		})
	}
}
