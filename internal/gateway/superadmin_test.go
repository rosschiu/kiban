// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
)

// fakeAuthzServer builds an httptest server standing in for authz's effective-access/can
// endpoint, returning exactly the status/body the test wants — the same "fake the upstream"
// approach the token/proxy test suites use for JWKS/registry.
func fakeAuthzServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/authz/effective-access/can" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header to be forwarded")
		}
		var req struct{ FeatureKey, Scope string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.FeatureKey != authzclient.AdminFeatureKey {
			t.Errorf("featureKey = %q, want %q", req.FeatureKey, authzclient.AdminFeatureKey)
		}
		if req.Scope != "global" {
			t.Errorf("scope = %q, want global", req.Scope)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func requestWithAuth(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/platform/admin/modules/foo/enable", nil)
	r.Header.Set("Authorization", "Bearer sometoken")
	r = r.WithContext(ContextWithAuth(context.Background(), AuthContext{Subject: "user-1"}))
	return r
}

func serveGuard(t *testing.T, client *AuthzAdminClient, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireSuperadmin(client, "registry.modules.enable")(next)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !called {
		t.Error("200 response but next handler was not invoked")
	}
	return rec
}

// TestGuard_FailClosed_OnDependencyUnavailable proves the guard's central fail-closed promise:
// authz's own DEPENDENCY_UNAVAILABLE decision (503 at authz's own HTTP layer) becomes a 503 at
// the gateway too — never a 401, never an allow.
func TestGuard_FailClosed_OnDependencyUnavailable(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusServiceUnavailable, `{"error":{"code":"AUTHORIZATION_UNAVAILABLE"}}`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_FailClosed_OnUnreachableAuthz proves a transport-level failure (authz down, DNS
// failure, timeout) also fails closed to 503, not 401/allow.
func TestGuard_FailClosed_OnUnreachableAuthz(t *testing.T) {
	// A closed listener: nothing answers on this URL at all.
	client := NewAuthzAdminClient("http://127.0.0.1:1")
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_FailClosed_OnUnrecognizedReason proves that an ALLOWED-shaped-but-unexpected body
// (e.g. allowed:false with a reason this guard doesn't recognize as a confirmed denial) is
// treated as uncertain, never as an allow and never treated as a definite denial either.
func TestGuard_FailClosed_OnUnrecognizedReason(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":false,"reason":"SOME_FUTURE_REASON","evidence":[]}}`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_FailClosed_OnMalformedBody proves an unparseable success-status body also fails
// closed rather than panicking or defaulting to allow.
func TestGuard_FailClosed_OnMalformedBody(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusOK, `not json`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_FailClosed_MissingAuthContext proves the guard never even calls authz without a
// validated AuthContext + raw bearer already present — its absence is itself an uncertainty,
// not a 401.
func TestGuard_FailClosed_MissingAuthContext(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/platform/admin/modules/foo/enable", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	// No AuthContext attached to the request context.
	rec := serveGuard(t, client, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_FailClosed_NilClient proves an unconfigured admin client (nil) also fails closed.
func TestGuard_FailClosed_NilClient(t *testing.T) {
	rec := serveGuard(t, nil, requestWithAuth(t))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestGuard_Denied_Returns403 proves a confirmed denial (a reason the ScopeGlobal decision can
// actually produce) maps to 403, distinct from the 503 fail-closed cases above.
func TestGuard_Denied_Returns403(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":false,"reason":"PLATFORM_ROLE_REQUIRED","evidence":[]}}`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestGuard_Allowed_PassesThrough proves the one success path actually reaches next.
func TestGuard_Allowed_PassesThrough(t *testing.T) {
	srv := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)
	rec := serveGuard(t, client, requestWithAuth(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (next handler reached)", rec.Code)
	}
}

// TestGuard_NoCaching proves back-to-back calls each re-check with authz (no positive decision
// caching) — two identical requests against a server that flips its answer must
// see the flip immediately, not a stale cached result.
func TestGuard_NoCaching(t *testing.T) {
	responses := []string{
		`{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`,
		`{"data":{"allowed":false,"reason":"PLATFORM_ROLE_REQUIRED","evidence":[]}}`,
	}
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responses[call]))
		call++
	}))
	defer srv.Close()

	client := NewAuthzAdminClient(srv.URL)

	rec1 := serveGuard(t, client, requestWithAuth(t))
	if rec1.Code != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200", rec1.Code)
	}
	rec2 := serveGuard(t, client, requestWithAuth(t))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("second call: status = %d, want 403 (must re-check, not reuse the first result)", rec2.Code)
	}
}
