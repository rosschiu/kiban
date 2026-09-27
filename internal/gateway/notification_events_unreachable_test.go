// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	notification "github.com/rosschiu/kiban/modules/notification/service"
)

// TestNotificationEvents_UnreachableThroughModuleProxy proves the
// S2S targeted-events endpoint (`POST /internal/notification/v1/companies/{id}/events`) is
// mounted on notification's `/internal/` prefix, deliberately NOT under `/api/notification/...`,
// and is never routed by the gateway. Two independent proofs, both against a REAL notification.Service (never a
// recording fake — a fake would trivially "prove" unreachability by construction):
//
//  1. The gateway's OWN `/internal/` prefix mux entry (routes.go) wins over the module proxy's
//     `/api/{moduleKey}/{rest...}` wildcard for any literal `/internal/...` inbound path — a
//     direct hit never reaches the module proxy at all.
//  2. Even if a caller tries to SMUGGLE the internal path as if it were a module-relative
//     sub-path (`/api/notification/internal/notification/v1/...`), the module proxy forwards
//     paths OPAQUELY (proxy.go's Rewrite touches only scheme/host): the
//     backend receives that exact literal path, which notification's own mux has no route for,
//     so it 404s at the module, never reaching handleSendEvent.
func TestNotificationEvents_UnreachableThroughModuleProxy(t *testing.T) {
	backend := newRealNotificationBackend(t)

	t.Run("direct hit on the gateway's own /internal/ prefix: 404 before the module proxy", func(t *testing.T) {
		handler := buildTestRoutes(t)
		req := httptest.NewRequest(http.MethodPost, "/internal/notification/v1/companies/co1/events", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (gateway's own /internal/ catch-all)", rec.Code)
		}
	})

	t.Run("smuggled as a module sub-path: the module proxy forwards it opaquely and the module itself 404s", func(t *testing.T) {
		registry := newRegistryStub(t)
		registry.set([]catalogRow{readyEntry(t, "notification", backend.URL)}, nil)
		proxySrv := newTestProxyServer(t, registry.server.URL)
		defer proxySrv.Close()

		resp, err := http.Post(proxySrv.URL+"/api/notification/internal/notification/v1/companies/co1/events", "application/json", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (notification's own mux has no route for this literal path — handleSendEvent must never be reached)", resp.StatusCode)
		}
	})
}

// newRealNotificationBackend builds a REAL notification.Service (real Routes(), no DB — the
// events route this test cares about 404s on path-shape alone, well before touching the store)
// behind httptest, standing in for the module backend the gateway's catalog would point at.
func newRealNotificationBackend(t *testing.T) *httptest.Server {
	t.Helper()
	svc := &notification.Service{}
	srv := httptest.NewServer(svc.Routes())
	t.Cleanup(srv.Close)
	return srv
}
