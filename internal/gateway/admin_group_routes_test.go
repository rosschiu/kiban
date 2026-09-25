// SPDX-License-Identifier: Apache-2.0

// Negative matrix for `/api/org/admin/*` group routes (same shape as
// admin_position_routes_test.go): missing bearer 401, non-superadmin 403, authz outage 503
// (fail-closed), forged x-user-* rejected, and (allowed) forwards verbatim to org with the
// company/group path segment preserved. The single-writer invariant's own 409
// GROUP_EXTERNALLY_MANAGED is org's own handler-level concern (internal/org/
// admin_group_http_test.go) — this file proves the gateway forwards faithfully, not that org
// enforces the invariant.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newAdminGroupTestFixture(t *testing.T, adminClient *AuthzAdminClient) *foundationTestFixture {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	mux := http.NewServeMux()
	mountAdminGroupRoutes(mux, verifier, nil, target, adminClient)
	return &foundationTestFixture{t: t, jwks: jwks, backend: backend, mux: mux}
}

var adminGroupRoutes = []struct {
	name   string
	method string
	path   string
	body   string
}{
	{"list", http.MethodGet, "/api/org/admin/companies/co-1/groups", ""},
	{"create", http.MethodPost, "/api/org/admin/companies/co-1/groups", `{"code":"support","name":"Support Team"}`},
	{"list-members", http.MethodGet, "/api/org/admin/groups/grp-1/members", ""},
	{"add-member", http.MethodPost, "/api/org/admin/groups/grp-1/members", `{"memberId":"mem-1"}`},
	{"remove-member", http.MethodDelete, "/api/org/admin/groups/grp-1/members/mem-1", ``},
}

func TestAdminGroupRoutes_MissingBearer_401(t *testing.T) {
	for _, rt := range adminGroupRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminGroupTestFixture(t, allowedAdminClient(t))
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

func TestAdminGroupRoutes_NonSuperadmin_403(t *testing.T) {
	for _, rt := range adminGroupRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminGroupTestFixture(t, deniedAdminClient(t))
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

func TestAdminGroupRoutes_AuthzOutage_503FailClosed(t *testing.T) {
	unreachable := NewAuthzAdminClient("http://127.0.0.1:1")
	for _, rt := range adminGroupRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminGroupTestFixture(t, unreachable)
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

func TestAdminGroupRoutes_ForgedUserHeader_Rejected400(t *testing.T) {
	for _, rt := range adminGroupRoutes {
		t.Run(rt.name, func(t *testing.T) {
			f := newAdminGroupTestFixture(t, allowedAdminClient(t))
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

func TestAdminGroupRoutes_Allowed_ForwardsToOrgWithPathPreserved(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		body         string
		wantFwdPath  string
		responsePath string
	}{
		{"list", http.MethodGet, "/api/org/admin/companies/co-1/groups", "", "/internal/org/companies/co-1/groups", "/internal/org/companies/co-1/groups"},
		{"create", http.MethodPost, "/api/org/admin/companies/co-1/groups", `{"code":"support","name":"Support Team"}`, "/internal/org/companies/co-1/groups", "/internal/org/companies/co-1/groups"},
		{"list-members", http.MethodGet, "/api/org/admin/groups/grp-1/members", "", "/internal/org/groups/grp-1/members", "/internal/org/groups/grp-1/members"},
		{"add-member", http.MethodPost, "/api/org/admin/groups/grp-1/members", `{"memberId":"mem-1"}`, "/internal/org/groups/grp-1/members", "/internal/org/groups/grp-1/members"},
		{"remove-member", http.MethodDelete, "/api/org/admin/groups/grp-1/members/mem-1", ``, "/internal/org/groups/grp-1/members/mem-1", "/internal/org/groups/grp-1/members/mem-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdminGroupTestFixture(t, allowedAdminClient(t))
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
