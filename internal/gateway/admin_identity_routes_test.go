// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/url"
	"testing"
)

func newAdminIdentityTestFixture(t *testing.T, adminClient *AuthzAdminClient) *foundationTestFixture {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	mux := http.NewServeMux()
	mountAdminIdentityRoutes(mux, verifier, nil, target, adminClient)
	return &foundationTestFixture{t: t, jwks: jwks, backend: backend, mux: mux}
}

var adminIdentityRoutes = []struct {
	name, method, path, body, forwarded string
}{
	{"global_get", http.MethodGet, "/api/platform/admin/mfa-policy/global", "", "/internal/identity/mfa-policy/global"},
	{"global_set", http.MethodPut, "/api/platform/admin/mfa-policy/global", `{"required":true,"method":"otp"}`, "/internal/identity/mfa-policy/global"},
	{"user_get", http.MethodGet, "/api/platform/admin/mfa-policy/users/sub-1", "", "/internal/identity/mfa-policy/subjects/sub-1"},
	{"user_set", http.MethodPut, "/api/platform/admin/mfa-policy/users/sub-1", `{"required":true,"method":"otp"}`, "/internal/identity/mfa-policy/subjects/sub-1"},
	{"user_clear", http.MethodDelete, "/api/platform/admin/mfa-policy/users/sub-1", "", "/internal/identity/mfa-policy/subjects/sub-1"},
	{"sync", http.MethodPost, "/api/platform/admin/mfa-policy/sync", "", "/internal/identity/mfa-policy/sync"},
}

func TestAdminIdentityRoutes_SuperadminForwardedWithBearer(t *testing.T) {
	f := newAdminIdentityTestFixture(t, allowedAdminClient(t))
	bearer := f.bearerFor("root")
	for _, rt := range adminIdentityRoutes {
		t.Run(rt.name, func(t *testing.T) {
			rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			call := f.backend.lastCall()
			if call.path != rt.forwarded {
				t.Errorf("forwarded path = %q, want %q", call.path, rt.forwarded)
			}
			if call.authValue != "Bearer "+bearer {
				t.Errorf("Authorization not forwarded verbatim: got %q", call.authValue)
			}
		})
	}
}

func TestAdminIdentityRoutes_NonSuperadmin_403_NeverReachesIdentity(t *testing.T) {
	f := newAdminIdentityTestFixture(t, deniedAdminClient(t))
	bearer := f.bearerFor("alice")
	for _, rt := range adminIdentityRoutes {
		t.Run(rt.name, func(t *testing.T) {
			before := len(f.backend.calls)
			rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if len(f.backend.calls) != before {
				t.Errorf("identity was called for a refused request")
			}
		})
	}
}

func TestAdminIdentityRoutes_IdentityRefusalRelayed(t *testing.T) {
	f := newAdminIdentityTestFixture(t, allowedAdminClient(t))
	f.backend.setResponse("/internal/identity/mfa-policy/subjects/ghost", http.StatusNotFound, `{"error":{"code":"NOT_FOUND","message":"user not found"}}`)
	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/platform/admin/mfa-policy/users/ghost", f.bearerFor("root"), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want identity's 404 relayed; body=%s", rec.Code, rec.Body.String())
	}
}
