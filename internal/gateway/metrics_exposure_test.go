// SPDX-License-Identifier: Apache-2.0

// Exposure pin: proves a gateway-forwarded `/api/<module>/metrics`
// never reaches a module's own bare `GET /metrics` mount. internal_exposure_test.go already
// proves the analogous claim for `/internal/*`; this file proves the metrics-specific one,
// which is a DIFFERENT mechanism — not a 404 fallback handler, but the fact that ModuleProxy
// forwards the request's path OPAQUELY (proxy.go's own comment: "touching ONLY Scheme/Host...
// leaves Path... byte-for-byte identical to the inbound request"), so a request that arrived as
// `/api/notification/metrics` is forwarded to the notification backend as that SAME path, never
// rewritten to `/metrics` — and every real service's own topMux (cmd/*/main.go /
// modules/*/service/cmd/main.go) registers `GET /metrics` at the bare path, under no module
// base-path prefix, so the forwarded request simply doesn't match it.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestModuleProxy_MetricsPathNeverReachesBackendMetricsRoute builds a fake module backend shaped
// EXACTLY like every real service's own topMux (cmd/*/main.go's own pattern): `GET /metrics` at
// the bare path serving distinctive content, everything else falling through to a 404. It then
// proxies `/api/notification/metrics` (the path a gateway-authenticated client would send) through
// the REAL ModuleProxy and asserts the response is NOT the backend's metrics content — proving
// the opaque-forwarding mechanism itself keeps a module's own `/metrics` gateway-unreachable,
// independent of any auth layer above the proxy.
func TestModuleProxy_MetricsPathNeverReachesBackendMetricsRoute(t *testing.T) {
	const metricsBody = "# HELP kiban_build_info ...\nkiban_build_info 1\n"

	backendMux := http.NewServeMux()
	backendMux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(metricsBody))
	})
	backendMux.HandleFunc("GET /api/notification/v1/companies/{companyId}/messages", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module business route reached"))
	})
	backend := httptest.NewServer(backendMux)
	defer backend.Close()

	registryStub := newRegistryStub(t)
	registryStub.set([]catalogRow{readyEntry(t, "notification", backend.URL)}, nil)

	proxyServer := newTestProxyServer(t, registryStub.server.URL)
	defer proxyServer.Close()

	// The exact path a gateway client sends (RoutesConfig's `/api/{moduleKey}/{rest...}`
	// pattern) — forwarded opaquely, so the backend sees this SAME path, not `/metrics`.
	resp, err := http.Get(proxyServer.URL + "/api/notification/metrics")
	if err != nil {
		t.Fatalf("GET /api/notification/metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		buf := make([]byte, len(metricsBody))
		n, _ := resp.Body.Read(buf)
		if string(buf[:n]) == metricsBody {
			t.Fatalf("gateway-forwarded /api/notification/metrics reached the backend's bare /metrics route — exposure pin violated")
		}
	}
	// The backend's topMux has no route matching "/api/notification/metrics" (only bare
	// "/metrics" and the module's own business route under a DIFFERENT path shape than what a
	// module actually registers under its base path in production — this asserts the negative:
	// whatever the backend answered, it wasn't the metrics content).

	// Sanity check the harness itself: the backend's bare /metrics route is directly reachable
	// (proving metricsBody would have been returned had the proxy rewritten the path) — this
	// guards against the test passing vacuously because backendMux was mis-wired.
	direct, err := http.Get(backend.URL + "/metrics")
	if err != nil {
		t.Fatalf("direct GET %s/metrics: %v", backend.URL, err)
	}
	defer direct.Body.Close()
	if direct.StatusCode != http.StatusOK {
		t.Fatalf("harness check: backend's own /metrics returned %d, want 200 (test would pass vacuously otherwise)", direct.StatusCode)
	}
}
