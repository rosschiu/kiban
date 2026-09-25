// SPDX-License-Identifier: Apache-2.0

// The generalized negative-security matrix (internal/testsec), applied
// to every gateway-owned route — foundation (/api/auth/*, /api/org/me/companies, /api/org/
// companies/{companyId}/members), the superadmin-guarded admin surfaces (/api/org/admin/
// positions, /api/org/admin/groups, /api/platform/admin/modules), and the bearer-only platform
// capability passthrough (/api/platform/capabilities*, /api/platform/catalog). Supersedes the ad
// hoc per-file matrices admin_position_routes_test.go/admin_group_routes_test.go hand-rolled
// — those files stay (they also prove the org-forwarding shape, which is
// out of testsec's scope), this file is the DRIFT PIN: every route mounted here is captured by a
// testsec.Recorder at the real mux.Handle call site, so a route added to any of the four
// mountXRoutes functions without a matching RouteSpec below fails TestGatewayRoutes_NoDrift.
package gateway

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/rosschiu/kiban/internal/testsec"
)

// gatewayMatrixFixture mounts every gateway route-group this file covers onto a single
// testsec.Recorder, backed by one fake JWKS server and one combined fake authz/org/registry
// backend (foundationBackend already stands in for all three — every route here only ever calls
// ONE backend per request).
func gatewayMatrixFixture(t *testing.T, adminClient *AuthzAdminClient) (*testsec.Recorder, *fakeJWKSServer, *foundationBackend) {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	rec := testsec.NewRecorder()
	mountFoundationRoutes(rec, verifier, nil, target, target, adminClient)
	mountAdminPositionRoutes(rec, verifier, nil, target, adminClient)
	mountAdminGroupRoutes(rec, verifier, nil, target, adminClient)
	mountPlatformRoutes(rec, verifier, nil, target, adminClient, nil)
	return rec, jwks, backend
}

// gatewayMatrixRoutes is the drift-pinned declaration: every route mounted by
// gatewayMatrixFixture, plus which guard class it carries. Pattern must match the mux.Handle
// call in the corresponding mountXRoutes function EXACTLY (TestGatewayRoutes_NoDrift enforces
// this).
var gatewayMatrixRoutes = []testsec.RouteSpec{
	// Superadmin guarded (RequireSuperadmin): 401/403/503/forged-header-400 all apply.
	{Name: "admin_position_list", Pattern: "GET /api/org/admin/companies/{companyId}/positions", Method: http.MethodGet, Path: "/api/org/admin/companies/co-1/positions"},
	{Name: "admin_position_create", Pattern: "POST /api/org/admin/companies/{companyId}/positions", Method: http.MethodPost, Path: "/api/org/admin/companies/co-1/positions", Body: `{"code":"cfo","title":"CFO"}`},
	{Name: "admin_position_assign", Pattern: "POST /api/org/admin/positions/{id}/assignments", Method: http.MethodPost, Path: "/api/org/admin/positions/pos-1/assignments", Body: `{"memberId":"mem-1"}`},
	{Name: "admin_position_end", Pattern: "POST /api/org/admin/assignments/{id}/end", Method: http.MethodPost, Path: "/api/org/admin/assignments/asg-1/end"},
	{Name: "admin_group_list", Pattern: "GET /api/org/admin/companies/{companyId}/groups", Method: http.MethodGet, Path: "/api/org/admin/companies/co-1/groups"},
	{Name: "admin_group_create", Pattern: "POST /api/org/admin/companies/{companyId}/groups", Method: http.MethodPost, Path: "/api/org/admin/companies/co-1/groups", Body: `{"code":"support","name":"Support"}`},
	{Name: "admin_group_members_list", Pattern: "GET /api/org/admin/groups/{id}/members", Method: http.MethodGet, Path: "/api/org/admin/groups/grp-1/members"},
	{Name: "admin_group_members_add", Pattern: "POST /api/org/admin/groups/{id}/members", Method: http.MethodPost, Path: "/api/org/admin/groups/grp-1/members", Body: `{"memberId":"mem-1"}`},
	{Name: "admin_group_members_remove", Pattern: "DELETE /api/org/admin/groups/{id}/members/{memberId}", Method: http.MethodDelete, Path: "/api/org/admin/groups/grp-1/members/mem-1"},
	{Name: "foundation_grants", Pattern: "POST /api/auth/grants", Method: http.MethodPost, Path: "/api/auth/grants", Body: `{"type":"user","typeId":"u-1","relation":"admin","objectType":"company","objectId":"co-1"}`},
	{Name: "platform_role_grant", Pattern: "POST /api/platform/admin/platform-roles", Method: http.MethodPost, Path: "/api/platform/admin/platform-roles", Body: `{"subjectId":"u-1","role":"kiban-superadmin"}`},
	{Name: "platform_role_revoke", Pattern: "DELETE /api/platform/admin/platform-roles/{role}/{subjectId}", Method: http.MethodDelete, Path: "/api/platform/admin/platform-roles/kiban-superadmin/u-1"},
	{Name: "platform_admin_module_enable", Pattern: "POST /api/platform/admin/modules/{key}/enable", Method: http.MethodPost, Path: "/api/platform/admin/modules/notification/enable"},
	{Name: "platform_admin_module_disable", Pattern: "POST /api/platform/admin/modules/{key}/disable", Method: http.MethodPost, Path: "/api/platform/admin/modules/notification/disable"},
	{Name: "platform_metrics", Pattern: "GET /api/platform/metrics", Method: http.MethodGet, Path: "/api/platform/metrics"},

	// Bearer-only (no additional gateway-side authorization decision — subject enforcement lives
	// downstream, or the route is a pure read passthrough): 403/503 skipped, forged-header still
	// applies via RequireAuth's own uniform x-user-* rejection.
	{Name: "foundation_can", Pattern: "POST /api/auth/effective-access/can", Method: http.MethodPost, Path: "/api/auth/effective-access/can", Body: `{"featureKey":"x","scope":"global"}`, SkipForbidden: true},
	{Name: "foundation_batch_can", Pattern: "POST /api/auth/effective-access/batch-can", Method: http.MethodPost, Path: "/api/auth/effective-access/batch-can", Body: `{"checks":[]}`, SkipForbidden: true},
	{Name: "foundation_summary", Pattern: "GET /api/auth/effective-access/summary", Method: http.MethodGet, Path: "/api/auth/effective-access/summary", SkipForbidden: true},
	{Name: "foundation_me_companies", Pattern: "GET /api/org/me/companies", Method: http.MethodGet, Path: "/api/org/me/companies", SkipForbidden: true},
	{Name: "foundation_member_directory", Pattern: "GET /api/org/companies/{companyId}/members", Method: http.MethodGet, Path: "/api/org/companies/co-1/members", SkipForbidden: true},
	{Name: "platform_capabilities", Pattern: "GET /api/platform/capabilities", Method: http.MethodGet, Path: "/api/platform/capabilities", SkipForbidden: true},
	{Name: "platform_capabilities_module", Pattern: "GET /api/platform/capabilities/{module}", Method: http.MethodGet, Path: "/api/platform/capabilities/notification", SkipForbidden: true},
	{Name: "platform_catalog", Pattern: "GET /api/platform/catalog", Method: http.MethodGet, Path: "/api/platform/catalog", SkipForbidden: true},
}

func TestGatewayRoutes_NegativeSecurityMatrix(t *testing.T) {
	allowedClient := allowedAdminClient(t)
	deniedClient := deniedAdminClient(t)
	unreachableClient := NewAuthzAdminClient("http://127.0.0.1:1")

	m := testsec.Matrix{
		Routes: gatewayMatrixRoutes,
		Allowed: func(t *testing.T) testsec.Fixture {
			rec, jwks, _ := gatewayMatrixFixture(t, allowedClient)
			return testsec.Fixture{Handler: rec, Bearer: jwks.signToken(t, tokenOpts{subject: "superadmin", audience: []string{testAudience}})}
		},
		Forbidden: func(t *testing.T) testsec.Fixture {
			rec, jwks, _ := gatewayMatrixFixture(t, deniedClient)
			return testsec.Fixture{Handler: rec, Bearer: jwks.signToken(t, tokenOpts{subject: "regular-user", audience: []string{testAudience}})}
		},
		Unavailable: func(t *testing.T) testsec.Fixture {
			rec, jwks, _ := gatewayMatrixFixture(t, unreachableClient)
			return testsec.Fixture{Handler: rec, Bearer: jwks.signToken(t, tokenOpts{subject: "someone", audience: []string{testAudience}})}
		},
		ForgedHeaders: map[string]string{"X-User-Id": "spoofed-superadmin"},
		ForgedBearer:  "valid",
		ForgedWant:    http.StatusBadRequest,
	}
	m.Run(t)
}

// TestGatewayRoutes_NoDrift is the drift pin: every route actually registered by the four
// mountXRoutes functions this file covers must have a matching RouteSpec in gatewayMatrixRoutes
// (by exact registration pattern). A route added to any of those functions without also adding a
// RouteSpec here fails this test.
func TestGatewayRoutes_NoDrift(t *testing.T) {
	rec, _, _ := gatewayMatrixFixture(t, allowedAdminClient(t))
	testsec.AssertNoDrift(t, rec.Registered, testsec.Matrix{Routes: gatewayMatrixRoutes}.Patterns())
}

// TestGatewayRoutes_NoDrift_CatchesUnmatrixedRoute proves the drift pin actually fires: mounts
// every real route PLUS one throwaway route no RouteSpec declares, and asserts
// testsec.MissingSpecs (the pure comparison AssertNoDrift wraps) reports it — using the pure
// function rather than AssertNoDrift itself, since a failing subtest unconditionally marks this
// test (and `go test`'s overall exit code) as failed regardless of any bool this test could
// inspect (testsec.MissingSpecs's own doc comment has the full account).
func TestGatewayRoutes_NoDrift_CatchesUnmatrixedRoute(t *testing.T) {
	rec, _, _ := gatewayMatrixFixture(t, allowedAdminClient(t))
	rec.HandleFunc("GET /api/org/admin/throwaway-unmatrixed-route", func(w http.ResponseWriter, r *http.Request) {})

	missing := testsec.MissingSpecs(rec.Registered, testsec.Matrix{Routes: gatewayMatrixRoutes}.Patterns())
	const want = "GET /api/org/admin/throwaway-unmatrixed-route"
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
