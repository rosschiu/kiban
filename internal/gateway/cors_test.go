// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedOrigins_DevDefault(t *testing.T) {
	got := allowedOrigins("")
	want := []string{"http://localhost:3000", "http://localhost:5173", "http://localhost"}
	if len(got) != len(want) {
		t.Fatalf("allowedOrigins(\"\") = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allowedOrigins(\"\")[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAllowedOrigins_KibanDomainSet(t *testing.T) {
	got := allowedOrigins("kiban.example.com")
	want := []string{"https://kiban.example.com"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("allowedOrigins(kiban.example.com) = %v, want %v", got, want)
	}
}

func TestCORS_PreflightAllowedOrigin_Returns204WithHeaders(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := CORS([]string{"http://localhost:5173"})(next)

	req := httptest.NewRequest(http.MethodOptions, "/api/auth/effective-access/summary", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if called {
		t.Error("a preflight OPTIONS must never reach the wrapped handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods missing on a preflight response")
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Access-Control-Allow-Headers missing on a preflight response")
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin (the response depends on the request's Origin)", got)
	}
}

func TestCORS_ActualRequestAllowedOrigin_HeaderAttachedAndForwarded(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{"http://localhost:5173"})(next)

	req := httptest.NewRequest(http.MethodGet, "/api/org/me/companies", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("a non-preflight request must reach the wrapped handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed origin", got)
	}
}

func TestCORS_DisallowedOrigin_NoHeadersButStillForwarded(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{"http://localhost:5173"})(next)

	req := httptest.NewRequest(http.MethodGet, "/api/org/me/companies", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("a disallowed-origin request still reaches the wrapped handler (RequireAuth/normal auth still gates it) — CORS only withholds the browser-trust header")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

func TestCORS_NoOriginHeader_PassesThroughUntouched(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{"http://localhost:5173"})(next)

	req := httptest.NewRequest(http.MethodGet, "/api/org/me/companies", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("a same-origin/non-browser request (no Origin header) must reach the wrapped handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty when no Origin header was sent", got)
	}
}

// TestCORS_AuthPathExempt proves `/auth/*` never gets this middleware's own
// Access-Control-Allow-Origin (Keycloak's own reverse-proxied response already carries its own —
// double-adding would produce an invalid multi-valued header).
func TestCORS_AuthPathExempt(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173") // stands in for Keycloak's own header
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{"http://localhost:5173"})(next)

	req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/protocol/openid-connect/token", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Header().Values("Access-Control-Allow-Origin")
	if len(got) != 1 {
		t.Fatalf("Access-Control-Allow-Origin values = %v, want exactly one (the downstream's own, untouched)", got)
	}
}

// TestRoutes_CORS_WiredEndToEnd proves Routes() itself applies CORS to the full mux (not just a
// unit-level CORS() call) — a preflight for a foundation route succeeds without ever reaching
// RequireAuth (no bearer set on this request at all).
func TestRoutes_CORS_WiredEndToEnd(t *testing.T) {
	handler := buildTestRoutes(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/auth/effective-access/summary", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (preflight succeeds even with zero auth)", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed dev origin", got)
	}
}

// TestCORS_KeycloakVerbatimMountsExempt proves the `/realms/` and `/resources/` mounts get the
// same exemption as `/auth/`: Keycloak's own Access-Control-Allow-Origin is the ONLY one on the
// response (two values on that header is a CORS failure in every browser).
func TestCORS_KeycloakVerbatimMountsExempt(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173") // Keycloak's own
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{"http://localhost:5173"})(next)

	for _, path := range []string{
		"/realms/kiban/protocol/openid-connect/token",
		"/resources/abc/login/keycloak/css/login.css",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Origin", "http://localhost:5173")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 {
			t.Errorf("%s: Access-Control-Allow-Origin values = %v, want exactly one", path, got)
		}
	}
}
