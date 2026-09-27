// SPDX-License-Identifier: Apache-2.0

// The gateway's listener IS the edge — in public
// mode the shared Traefik forwards the whole host to it — so a bare `GET /metrics` mount on the
// gateway would be reachable unauthenticated from the internet. The
// gateway therefore mounts no bare `/metrics` at all; its own exposition is served ONLY behind
// the superadmin guard at `GET /api/platform/metrics`. This test pins both halves with a
// Metrics registry wired in, exactly as cmd/gateway/main.go wires it.
package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

func TestGateway_BareMetricsPathIsNotMountedOnTheEdge(t *testing.T) {
	handler := buildTestRoutesWithMetrics(t)

	for _, path := range []string{"/metrics", "/metrics/", "/METRICS"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body := rec.Body.String()
		// The SPA static fallback may legitimately answer 200 text/html for any unknown GET; what
		// must never happen is Prometheus exposition content (or its content type) on the edge.
		if strings.Contains(body, "kiban_build_info") || strings.Contains(body, "# TYPE") ||
			strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=") {
			t.Fatalf("GET %s served Prometheus exposition unauthenticated on the edge listener — the v0.1.0 blocker regressed (status %d)", path, rec.Code)
		}
	}
}

func TestGateway_OperatorMetricsRouteRequiresAuth(t *testing.T) {
	handler := buildTestRoutesWithMetrics(t)

	req := httptest.NewRequest(http.MethodGet, "/api/platform/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/platform/metrics without a bearer: got %d, want 401 (RequireAuth + RequireSuperadmin guard)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "kiban_build_info") {
		t.Fatalf("unauthenticated /api/platform/metrics leaked exposition content")
	}
}

// buildTestRoutesWithMetrics is buildTestRoutes (static_test.go) plus a real metrics.Registry,
// so the "no bare mount" claim is tested against the configuration that actually ships, not a
// nil-Metrics shortcut.
func buildTestRoutesWithMetrics(t *testing.T) http.Handler {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier, err := NewTokenVerifier(context.Background(), jwks.URL+"/certs", testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(registrySrv.Close)
	catalog := NewCatalogClient(registrySrv.URL, nil)

	keycloakSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(keycloakSrv.Close)

	return Routes(RoutesConfig{
		Verifier:        verifier,
		Catalog:         catalog,
		RegistryBaseURL: registrySrv.URL,
		KeycloakBaseURL: keycloakSrv.URL,
		AdminClient:     NewAuthzAdminClient(registrySrv.URL),
		StaticDir:       "",
		AuthzBaseURL:    registrySrv.URL,
		OrgBaseURL:      registrySrv.URL,
		IdentityBaseURL: registrySrv.URL,
		Metrics:         metrics.New("gateway", "test", "test").EnableGatewayUpstream(),
	})
}
