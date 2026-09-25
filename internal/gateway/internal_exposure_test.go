// SPDX-License-Identifier: Apache-2.0

// Exposure pins. `/internal/*` is the gateway's own reserved namespace
// (routes.go's own comment: "gateway-owned namespace that must never be reachable from outside
// the edge") — every downstream service (authz/org/registry/each module) exposes its real S2S
// API under an `/internal/...` path on ITS OWN process, never proxied verbatim to a browser
// through the gateway. TestStatic_InternalPathAlwaysNotFound (static_test.go) already proved the
// status code; this file (a) widens that probe to a representative path per downstream service
// (registry, authz, org, and all four modules' own `/internal/...` S2S surfaces) and (b) proves
// the STRUCTURAL guarantee directly: none of the patterns any mountXRoutes function in this
// package registers begins with "/internal" — the reachability proof isn't just "these sample
// paths happened to 404 today", it's "there is no registered pattern under /internal at all",
// so a future route added under /internal/... by mistake is caught here even before anyone
// thinks to add it to the probe list below.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/testsec"
)

// TestInternalPaths_NeverExternallyRoutable_ProbeSweep probes a representative internal path per
// downstream service through the FULL gateway mux (buildTestRoutes, static_test.go) and asserts
// each resolves to writeInternalNotFound specifically (404 status AND errenv.CodeNotFound body),
// not merely "some 404" a different fallback handler could also produce.
func TestInternalPaths_NeverExternallyRoutable_ProbeSweep(t *testing.T) {
	handler := buildTestRoutes(t)

	probes := []string{
		"/internal/authz/effective-access/can",
		"/internal/authz/effective-access/batch-can",
		"/internal/org/me/companies",
		"/internal/org/companies/co-1/positions",
		"/internal/org/companies/co-1/groups",
		"/internal/platform/modules/notification/enable",
		"/internal/notification/v1/companies/co-1/events",
		"/internal/timesheet/v1/companies/co-1/config",
		"/internal/docs/v1/companies/co-1/documents",
		"/internal/helpdesk/v1/companies/co-1/tickets",
		"/internal/anything/at/all",
	}
	for _, path := range probes {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, path, strings.NewReader(""))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s: status = %d, want 404", method, path, rec.Code)
				continue
			}
			if !strings.Contains(rec.Body.String(), string(errenv.CodeNotFound)) {
				t.Errorf("%s %s: body = %s, want the writeInternalNotFound envelope (code %q)", method, path, rec.Body.String(), errenv.CodeNotFound)
			}
		}
	}
}

// TestInternalPaths_NoRegisteredPatternUnderInternal is the structural half of the exposure pin:
// every route this package's own negative-security matrix (security_matrix_test.go) knows about
// — the full set mountFoundationRoutes/mountAdminPositionRoutes/mountAdminGroupRoutes/
// mountPlatformRoutes register — must have a pattern outside "/internal/". Combined with routes.go
// mounting "/internal/" itself directly to writeInternalNotFound (never delegating to any
// mountXRoutes function), this proves there is no code path by which an authenticated OR
// unauthenticated request can reach anything other than writeInternalNotFound under that prefix.
func TestInternalPaths_NoRegisteredPatternUnderInternal(t *testing.T) {
	rec, _, _ := gatewayMatrixFixture(t, allowedAdminClient(t))
	for _, pattern := range rec.Registered {
		// A pattern is "METHOD /path..."; check the path half.
		path := pattern
		if i := strings.IndexByte(pattern, ' '); i >= 0 {
			path = pattern[i+1:]
		}
		if strings.HasPrefix(path, "/internal") {
			t.Errorf("route %q is registered under /internal — the gateway's own reserved, externally-unroutable namespace", pattern)
		}
	}
	// Guard against the check above passing vacuously if nothing were registered at all.
	if len(rec.Registered) < len(testsec.Matrix{Routes: gatewayMatrixRoutes}.Patterns()) {
		t.Fatalf("only %d routes were registered, expected at least %d — the fixture didn't mount what the matrix expects",
			len(rec.Registered), len(testsec.Matrix{Routes: gatewayMatrixRoutes}.Patterns()))
	}
}
