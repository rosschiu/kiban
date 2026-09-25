// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// TestSecurityHeaders_OnGatewayResponses proves the baseline headers ride on every
// gateway-originated response through the real Routes() wiring — a JSON error the gateway
// writes itself, a CORS-decorated response — with HSTS only on a TLS-served request (or a
// trusted edge asserting https), and that Keycloak-proxied responses are left untouched.
func TestSecurityHeaders_OnGatewayResponses(t *testing.T) {
	handler := buildTestRoutes(t)
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	t.Run("gateway-written 404 over plain HTTP: headers, no HSTS", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/x", nil))
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q on plain HTTP, want none", got)
		}
	})

	t.Run("TLS-served: HSTS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/foo/x", nil)
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (no bearer)", rec.Code)
		}
		if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
			t.Errorf("Strict-Transport-Security = %q, want max-age=31536000", got)
		}
	})

	t.Run("untrusted X-Forwarded-Proto: https earns no HSTS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/x", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q, want none (TrustProxyHeaders=false)", got)
		}
	})

	t.Run("Keycloak mounts untouched", func(t *testing.T) {
		for _, path := range []string{"/auth/realms/kiban/x", "/realms/kiban/x", "/resources/x/y"} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d, want 200 from the Keycloak stub", path, rec.Code)
			}
			for k := range want {
				if got := rec.Header().Get(k); got != "" {
					t.Errorf("%s: %s = %q, want Keycloak's own headers only", path, k, got)
				}
			}
		}
	})
}

// TestSecurityHeaders_TrustedProxyHTTPS proves the one topology where a plain-HTTP request
// earns HSTS: TrustProxyHeaders with the edge asserting X-Forwarded-Proto: https.
func TestSecurityHeaders_TrustedProxyHTTPS(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	handler := securityHeaders(true, ok)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security = %q, want max-age=31536000", got)
	}
	// Write without an explicit WriteHeader still gets the headers.
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

// TestSecurityHeaders_ProxiedModuleResponse_Overridden proves a module upstream that sends its
// own (weaker) value for one of these headers ends up with exactly ONE, the edge's, on the
// response the client sees — never two values (ReverseProxy copies upstream headers with Add).
func TestSecurityHeaders_ProxiedModuleResponse_Overridden(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer backend.Close()
	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "foo", backend.URL)}, nil)
	proxy := NewModuleProxy(NewCatalogClient(reg.server.URL, nil))
	handler := securityHeaders(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("moduleKey", "foo")
		proxy.ServeHTTP(w, r)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/foo/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Values("X-Frame-Options"); len(got) != 1 || got[0] != "DENY" {
		t.Errorf("X-Frame-Options = %v, want exactly [DENY]", got)
	}
	if got := rec.Header().Values("X-Content-Type-Options"); len(got) != 1 {
		t.Errorf("X-Content-Type-Options = %v, want exactly one value", got)
	}
}

// TestProxy_OverLimitBody_413NotUpstream503 proves a request body over limitBody's cap is
// answered 413 PAYLOAD_TOO_LARGE (the client's fault) — not 503 MODULE_UNAVAILABLE — and is
// NOT counted in kiban_gateway_upstream_requests_total (the module never received it; an
// attacker must not be able to drive the "module unreachable" metric with oversized uploads).
// A small cap stands in for the 32 MB one: the code path is the same http.MaxBytesError.
func TestProxy_OverLimitBody_413NotUpstream503(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "foo", backend.URL)}, nil)
	proxy := NewModuleProxy(NewCatalogClient(reg.server.URL, nil))
	mreg := metrics.New("gateway", "test", "test").EnableGatewayUpstream()
	proxy.Metrics = mreg
	gw := httptest.NewServer(limitBody(1024, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("moduleKey", "foo")
		proxy.ServeHTTP(w, r)
	})))
	defer gw.Close()

	resp, err := http.Post(gw.URL+"/api/foo/upload", "application/octet-stream", strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "PAYLOAD_TOO_LARGE" {
		t.Errorf("code = %q, want PAYLOAD_TOO_LARGE", code)
	}

	rec := httptest.NewRecorder()
	mreg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := rec.Body.String(); strings.Contains(body, `kiban_gateway_upstream_requests_total{module="foo"`) {
		t.Errorf("upstream metric recorded for an over-limit body:\n%s", body)
	}

	// A body within the cap still reaches the module.
	resp2, err := http.Post(gw.URL+"/api/foo/upload", "application/octet-stream", strings.NewReader("small"))
	if err != nil {
		t.Fatalf("POST small: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("small body status = %d, want 204", resp2.StatusCode)
	}
}

// TestFixedProxy_OverLimitBody_413 proves the fixed-target proxies (platform/foundation/auth)
// share the same 413 mapping at their 1 MB cap.
func TestFixedProxy_OverLimitBody_413(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	gw := httptest.NewServer(limitBody(1024, newFixedProxy(target, nil)))
	defer gw.Close()

	resp, err := http.Post(gw.URL+"/api/platform/catalog", "application/json", strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "PAYLOAD_TOO_LARGE" {
		t.Errorf("code = %q, want PAYLOAD_TOO_LARGE", code)
	}
}

// TestForwardedFor_EveryProxy proves each proxy kind hands its upstream the EDGE's view of the
// client in X-Forwarded-For: the peer IP always; a client-supplied value only when
// TrustProxyHeaders (prepended, as the trusted edge's own chain), dropped otherwise.
func TestForwardedFor_EveryProxy(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-For")
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "foo", backend.URL)}, nil)
	moduleProxy := NewModuleProxy(NewCatalogClient(reg.server.URL, nil))

	proxies := map[string]http.Handler{
		"module": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.SetPathValue("moduleKey", "foo")
			moduleProxy.ServeHTTP(w, r)
		}),
		"fixed":          newFixedProxy(target, nil),
		"subject-scoped": newSubjectScopedProxy(target, "/internal/x"),
		"auth":           NewAuthProxy(target, false, nil),
		"verbatim":       NewKeycloakVerbatimProxy(target, false, nil),
	}
	for name, proxy := range proxies {
		for _, trust := range []bool{false, true} {
			handler := clientForwardedFor(trust, proxy)
			req := httptest.NewRequest(http.MethodGet, "/api/foo/x", nil)
			req.RemoteAddr = "203.0.113.9:4444"
			req.Header.Set("X-Forwarded-For", "10.0.0.1")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			want := "203.0.113.9"
			if trust {
				want = "10.0.0.1, 203.0.113.9"
			}
			if got != want {
				t.Errorf("%s trust=%v: upstream X-Forwarded-For = %q, want %q", name, trust, got, want)
			}
		}
	}
}
