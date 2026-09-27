// SPDX-License-Identifier: Apache-2.0

// Package testsec is the shared negative-security matrix: one place that generalizes the ad hoc
// 401/403/503/forged-header pattern internal/gateway/admin_position_routes_test.go and
// admin_group_routes_test.go established, so every guarded route in the gateway and all four module HTTP layers is proven, not just
// the ones a human remembered to hand-write a matrix for.
//
// Two independent pieces:
//
//   - Matrix (this file): for each declared RouteSpec, drives missing-bearer (401),
//     malformed-bearer (401), valid-but-forbidden (403), dependency-unavailable (503), and
//     forged-inbound-identity-header assertions against caller-supplied fixtures. Callers own
//     how a fixture is built (a real mux over a fake JWKS + fake downstream, matching every
//     existing *_test.go in this codebase) — this package only owns the request-shape and
//     assertion logic, never fixture construction, so it has zero dependency on any specific
//     package's wiring.
//
//   - Recorder + AssertNoDrift (recorder.go): the drift pin. A route mounted through a Recorder
//     instead of a bare *http.ServeMux is captured by pattern string at registration time (the
//     REAL mux.Handle/HandleFunc call, not a hand-maintained parallel list) — AssertNoDrift then
//     fails the test if any registered pattern has no corresponding matrix entry, so a route
//     added to a package's mount function without also adding a RouteSpec breaks `make check`.
package testsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RouteSpec describes one route to run the negative-security matrix against.
type RouteSpec struct {
	// Name is a short, unique label for t.Run subtests.
	Name string
	// Pattern is the EXACT string the route is registered with (e.g.
	// "GET /api/org/admin/companies/{companyId}/positions") — used only for the drift check
	// (matched 1:1 against Recorder.Registered), never to build a request.
	Pattern string
	// Method and Path build the concrete request this route's assertions send — Path has every
	// {wildcard} already substituted with a sample value (e.g.
	// "/api/org/admin/companies/co-1/positions").
	Method string
	Path   string
	// Body is the request body (may be empty for GET/DELETE-shaped routes).
	Body string

	// SkipForbidden marks a route that has no additional per-request authorization decision
	// beyond bearer validation (e.g. the foundation "can"/"batch-can" fixed proxies, whose
	// subject-scoping is enforced downstream, not at this layer) — the 403 and 503 assertions
	// don't apply and are skipped; the caller must document why.
	SkipForbidden bool
}

// Fixture is one scenario's ready-to-drive handler plus (optionally) a bearer token already
// minted for it.
type Fixture struct {
	Handler http.Handler
	Bearer  string
}

// Matrix bundles a route list with the fixture builders needed to run every assertion. Every
// builder is called once per (scenario, route) — cheap fixtures are expected (in-process
// httptest servers), matching every existing *_test.go in this codebase.
type Matrix struct {
	Routes []RouteSpec

	// Allowed builds the fixture for an authorized, dependency-healthy request — the base case
	// missing-bearer/malformed-bearer are layered on top of (with the bearer withheld/corrupted)
	// and forged-header runs against directly (with a valid bearer, to prove the header — not the
	// bearer — is what's rejected/ignored).
	Allowed func(t *testing.T) Fixture
	// Forbidden builds the fixture for a valid bearer that is authenticated but not authorized
	// (non-member/non-admin) — skipped for routes with SkipForbidden.
	Forbidden func(t *testing.T) Fixture
	// Unavailable builds the fixture for a dependency-down (authz/org unreachable) scenario —
	// skipped for routes with SkipForbidden (same routes that have no downstream authz call to
	// fail).
	Unavailable func(t *testing.T) Fixture

	// MalformedBearer is a syntactically-invalid bearer value (not a valid JWT) used for the
	// malformed-token case.
	MalformedBearer string

	// ForgedHeaders are the inbound identity headers a real client must never be able to set
	// (x-user-*, x-kiban-*, ...) that this suite proves are rejected or ignored.
	ForgedHeaders map[string]string
	// ForgedBearer selects which bearer to attach alongside ForgedHeaders: "" sends no bearer
	// (proving the header cannot substitute for authentication — the shape module routes use,
	// since they have no header-rejection layer of their own); "valid" attaches Allowed's own
	// minted bearer (the shape gateway routes use, since RequireAuth rejects the header outright
	// regardless of an otherwise-valid bearer).
	ForgedBearer string // "" or "valid"
	// ForgedWant is the expected status for the forged-header request.
	ForgedWant int
}

func doRequest(t *testing.T, h http.Handler, method, path, bearer, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Run drives every assertion in the matrix for every route.
func (m Matrix) Run(t *testing.T) {
	t.Helper()
	for _, rt := range m.Routes {
		rt := rt
		t.Run(rt.Name, func(t *testing.T) {
			t.Run("missing_bearer_401", func(t *testing.T) {
				f := m.Allowed(t)
				rec := doRequest(t, f.Handler, rt.Method, rt.Path, "", rt.Body, nil)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401 with no bearer, body=%s", rec.Code, rec.Body.String())
				}
			})

			t.Run("malformed_bearer_401", func(t *testing.T) {
				f := m.Allowed(t)
				bearer := m.MalformedBearer
				if bearer == "" {
					bearer = "not-a-jwt"
				}
				rec := doRequest(t, f.Handler, rt.Method, rt.Path, bearer, rt.Body, nil)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401 with a malformed bearer, body=%s", rec.Code, rec.Body.String())
				}
			})

			if !rt.SkipForbidden {
				t.Run("valid_non_member_403", func(t *testing.T) {
					f := m.Forbidden(t)
					rec := doRequest(t, f.Handler, rt.Method, rt.Path, f.Bearer, rt.Body, nil)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want 403 for an authenticated-but-unauthorized bearer, body=%s", rec.Code, rec.Body.String())
					}
				})

				t.Run("authz_unavailable_503", func(t *testing.T) {
					f := m.Unavailable(t)
					rec := doRequest(t, f.Handler, rt.Method, rt.Path, f.Bearer, rt.Body, nil)
					if rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("status = %d, want 503 (fail-closed on dependency outage), body=%s", rec.Code, rec.Body.String())
					}
				})
			}

			if len(m.ForgedHeaders) > 0 {
				t.Run("forged_identity_header", func(t *testing.T) {
					f := m.Allowed(t)
					bearer := ""
					if m.ForgedBearer == "valid" {
						bearer = f.Bearer
					}
					rec := doRequest(t, f.Handler, rt.Method, rt.Path, bearer, rt.Body, m.ForgedHeaders)
					if rec.Code != m.ForgedWant {
						t.Fatalf("status = %d, want %d for a forged inbound identity header, body=%s", rec.Code, m.ForgedWant, rec.Body.String())
					}
				})
			}
		})
	}
}

// Patterns returns every route's registration Pattern, for AssertNoDrift.
func (m Matrix) Patterns() []string {
	out := make([]string, 0, len(m.Routes))
	for _, rt := range m.Routes {
		out = append(out, rt.Pattern)
	}
	return out
}
