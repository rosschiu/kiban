// SPDX-License-Identifier: Apache-2.0

// The shared negative-security matrix (internal/testsec), applied to every bearer-guarded route
// in this module's own route table (http.go's mountRoutes). Excluded deliberately: /health, /ready
// (unauthenticated liveness probes) and the S2S
// `/internal/notification/v1/companies/{companyId}/events` route (handleSendEvent) — it is NOT
// gated by withAuth at all (it does its own authz.Can check inline) and structurally can never be
// reached through the gateway's module proxy (proxy.go only forwards paths starting
// `/api/{moduleKey}`) — proven unreachable via the gateway's own exposure pin
// (internal/gateway/internal_exposure_test.go) and exercised by chaos_test.go. Drift-pinned: every
// OTHER route mountRoutes registers is captured by a testsec.Recorder, so a route added without a
// matching RouteSpec fails TestRoutes_NoDrift.
package notification

import (
	"net/http"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/testchaos"
	"github.com/rosschiu/kiban/internal/testsec"
)

var notificationMatrixRoutes = []testsec.RouteSpec{
	{Name: "list_channels", Pattern: "GET /api/notification/v1/companies/{companyId}/channels", Method: http.MethodGet, Path: "/api/notification/v1/companies/co-1/channels"},
	{Name: "create_channel", Pattern: "POST /api/notification/v1/companies/{companyId}/channels", Method: http.MethodPost, Path: "/api/notification/v1/companies/co-1/channels", Body: `{"name":"c"}`},
	{Name: "get_channel", Pattern: "GET /api/notification/v1/companies/{companyId}/channels/{channelId}", Method: http.MethodGet, Path: "/api/notification/v1/companies/co-1/channels/chan-1"},
	{Name: "delete_channel", Pattern: "DELETE /api/notification/v1/companies/{companyId}/channels/{channelId}", Method: http.MethodDelete, Path: "/api/notification/v1/companies/co-1/channels/chan-1"},
	{Name: "subscribe", Pattern: "POST /api/notification/v1/companies/{companyId}/channels/{channelId}/subscriptions", Method: http.MethodPost, Path: "/api/notification/v1/companies/co-1/channels/chan-1/subscriptions"},
	{Name: "unsubscribe", Pattern: "DELETE /api/notification/v1/companies/{companyId}/channels/{channelId}/subscriptions/me", Method: http.MethodDelete, Path: "/api/notification/v1/companies/co-1/channels/chan-1/subscriptions/me"},
	{Name: "list_inbox", Pattern: "GET /api/notification/v1/companies/{companyId}/messages", Method: http.MethodGet, Path: "/api/notification/v1/companies/co-1/messages"},
	{Name: "send_message", Pattern: "POST /api/notification/v1/companies/{companyId}/messages", Method: http.MethodPost, Path: "/api/notification/v1/companies/co-1/messages", Body: `{}`},
	{Name: "mark_read", Pattern: "POST /api/notification/v1/companies/{companyId}/messages/{messageId}/read", Method: http.MethodPost, Path: "/api/notification/v1/companies/co-1/messages/msg-1/read"},
}

func TestNotificationRoutes_NegativeSecurityMatrix(t *testing.T) {
	m := testsec.Matrix{
		Routes: notificationMatrixRoutes,
		Allowed: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		Forbidden: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-nobody")}
		},
		Unavailable: func(t *testing.T) testsec.Fixture {
			f := newNotifChaosFixture(t, testchaos.RefusedURL(), "", 300*time.Millisecond)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		// See timesheet's own matrix file for why this is the module-shape forged-header proof:
		// notification's withAuth never reads an inbound x-user-*/x-kiban-* header, so the header
		// is proven unable to substitute for a bearer (still 401 with no Authorization set),
		// rather than proving a gateway-style outright-rejection status.
		ForgedHeaders: map[string]string{"X-User-Id": "spoofed-admin", "X-Kiban-Role": "kiban-superadmin"},
		ForgedBearer:  "",
		ForgedWant:    http.StatusUnauthorized,
	}
	m.Run(t)
}

func TestNotificationRoutes_NoDrift(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)

	var registered []string
	for _, p := range rec.Registered {
		if p == "GET /health" || p == "GET /ready" || p == "POST /internal/notification/v1/companies/{companyId}/events" {
			continue
		}
		registered = append(registered, p)
	}
	testsec.AssertNoDrift(t, registered, testsec.Matrix{Routes: notificationMatrixRoutes}.Patterns())
}

func TestNotificationRoutes_NoDrift_CatchesUnmatrixedRoute(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)
	rec.HandleFunc("GET /api/notification/v1/companies/{companyId}/throwaway-unmatrixed", func(w http.ResponseWriter, r *http.Request) {})

	allowed := append(testsec.Matrix{Routes: notificationMatrixRoutes}.Patterns(),
		"GET /health", "GET /ready", "POST /internal/notification/v1/companies/{companyId}/events")
	missing := testsec.MissingSpecs(rec.Registered, allowed)
	const want = "GET /api/notification/v1/companies/{companyId}/throwaway-unmatrixed"
	found := false
	for _, m := range missing {
		if m == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the throwaway route %q to be reported missing from the matrix, got missing=%v", want, missing)
	}
}

// TestAllModuleRoutes_RequireBearer_401 is the "every module route requires bearer" sweep,
// derived directly from the matrix's own route list (not a second
// hand-maintained list) — every route this module registers (except /health, /ready) rejects a
// bearer-less request with 401.
func TestAllModuleRoutes_RequireBearer_401(t *testing.T) {
	f := newHTTPFixture(t, nil)
	for _, rt := range notificationMatrixRoutes {
		t.Run(rt.Name, func(t *testing.T) {
			rec := f.do(t, rt.Method, rt.Path, "", rt.Body, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: status = %d, want 401 with no bearer", rt.Method, rt.Path, rec.Code)
			}
		})
	}
}
