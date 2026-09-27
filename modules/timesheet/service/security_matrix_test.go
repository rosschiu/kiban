// SPDX-License-Identifier: Apache-2.0

// The shared negative-security matrix (internal/testsec), applied to
// every route in this module's own route table (http.go's mountRoutes). Drift-pinned: every
// route mountRoutes registers is captured by a testsec.Recorder at the real mux.HandleFunc call
// site, so a route added to mountRoutes without a matching RouteSpec below fails
// TestRoutes_NoDrift.
package timesheet

import (
	"net/http"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/testchaos"
	"github.com/rosschiu/kiban/internal/testsec"
)

// timesheetMatrixRoutes mirrors http.go's mountRoutes exactly (Pattern must match the
// mux.HandleFunc call verbatim — TestRoutes_NoDrift enforces this). /health and /ready are
// intentionally excluded — genuinely unauthenticated liveness/readiness probes, not part of the
// authenticated API surface this matrix covers.
var timesheetMatrixRoutes = []testsec.RouteSpec{
	{Name: "get_config", Pattern: "GET /api/timesheet/v1/companies/{companyId}/config", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/config"},
	{Name: "update_config", Pattern: "PUT /api/timesheet/v1/companies/{companyId}/config", Method: http.MethodPut, Path: "/api/timesheet/v1/companies/co-1/config", Body: `{}`},
	{Name: "list_projects", Pattern: "GET /api/timesheet/v1/companies/{companyId}/projects", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/projects"},
	{Name: "create_project", Pattern: "POST /api/timesheet/v1/companies/{companyId}/projects", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/projects", Body: `{"name":"P"}`},
	{Name: "update_project", Pattern: "PUT /api/timesheet/v1/companies/{companyId}/projects/{projectId}", Method: http.MethodPut, Path: "/api/timesheet/v1/companies/co-1/projects/proj-1", Body: `{"name":"P"}`},
	{Name: "list_approvers", Pattern: "GET /api/timesheet/v1/companies/{companyId}/approvers", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/approvers"},
	{Name: "assign_approver", Pattern: "POST /api/timesheet/v1/companies/{companyId}/approvers", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/approvers", Body: `{"memberId":"mem-1"}`},
	{Name: "list_entries", Pattern: "GET /api/timesheet/v1/companies/{companyId}/entries", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/entries"},
	{Name: "upsert_entry", Pattern: "POST /api/timesheet/v1/companies/{companyId}/entries", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/entries", Body: `{}`},
	{Name: "delete_entry", Pattern: "DELETE /api/timesheet/v1/companies/{companyId}/entries/{entryId}", Method: http.MethodDelete, Path: "/api/timesheet/v1/companies/co-1/entries/entry-1"},
	{Name: "list_submissions", Pattern: "GET /api/timesheet/v1/companies/{companyId}/submissions", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/submissions"},
	{Name: "submit_week", Pattern: "POST /api/timesheet/v1/companies/{companyId}/submissions", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/submissions", Body: `{}`},
	{Name: "get_submission", Pattern: "GET /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}", Method: http.MethodGet, Path: "/api/timesheet/v1/companies/co-1/submissions/sub-1"},
	{Name: "approve_submission", Pattern: "POST /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}/approve", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/submissions/sub-1/approve"},
	{Name: "reject_submission", Pattern: "POST /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}/reject", Method: http.MethodPost, Path: "/api/timesheet/v1/companies/co-1/submissions/sub-1/reject"},
}

// matrixFixture builds a *httpFixture (http_test.go's own type) whose authz backing decides
// every request: authzURL/orgURL "" mean "use ordinary, always-denying fakes" (nobody in the
// empty companyMembers/admins maps is ever authorized — deliberate: none of this matrix's
// assertions ever need a genuinely ALLOWED response, only the guard's rejection shapes, see this
// file's own header comment); a non-empty override URL (testchaos.RefusedURL()) stands in for a
// down dependency.
func timesheetMatrixFixture(t *testing.T, authzOverride string) *httpFixture {
	t.Helper()
	orgSrv := newFakeOrg(t, nil)
	authzURL := authzOverride
	if authzURL == "" {
		authzURL = newFakeAuthz(t, nil, nil).URL
	}
	return newChaosHTTPFixture(t, authzURL, orgSrv.URL, 5*time.Second)
}

func TestTimesheetRoutes_NegativeSecurityMatrix(t *testing.T) {
	m := testsec.Matrix{
		Routes: timesheetMatrixRoutes,
		Allowed: func(t *testing.T) testsec.Fixture {
			f := timesheetMatrixFixture(t, "")
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		Forbidden: func(t *testing.T) testsec.Fixture {
			f := timesheetMatrixFixture(t, "")
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-nobody")}
		},
		Unavailable: func(t *testing.T) testsec.Fixture {
			f := timesheetMatrixFixture(t, testchaos.RefusedURL())
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		// timesheet's HTTP layer never reads an inbound x-user-*/x-kiban-* header at all
		// (withAuth derives the subject exclusively from the verified bearer) — there is no
		// rejection mechanism to prove 400 for, unlike the gateway's RequireAuth. What IS provable
		// is that the header cannot substitute for a bearer: send it with NO Authorization header
		// and confirm the request still 401s exactly like the plain missing-bearer case.
		ForgedHeaders: map[string]string{"X-User-Id": "spoofed-admin", "X-Kiban-Role": "kiban-superadmin"},
		ForgedBearer:  "",
		ForgedWant:    http.StatusUnauthorized,
	}
	m.Run(t)
}

// TestTimesheetRoutes_NoDrift is the drift pin: mounts the real mountRoutes through a
// testsec.Recorder and asserts every pattern it registers (other than /health, /ready — excluded
// deliberately, see timesheetMatrixRoutes's own comment) has a matching RouteSpec.
func TestTimesheetRoutes_NoDrift(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)

	var registered []string
	for _, p := range rec.Registered {
		if p == "GET /health" || p == "GET /ready" {
			continue
		}
		registered = append(registered, p)
	}
	testsec.AssertNoDrift(t, registered, testsec.Matrix{Routes: timesheetMatrixRoutes}.Patterns())
}

// TestTimesheetRoutes_NoDrift_CatchesUnmatrixedRoute proves the drift pin fires: adds one
// throwaway route no RouteSpec declares and asserts testsec.MissingSpecs reports it (the pure
// comparison — see internal/testsec's own doc comment for why AssertNoDrift itself can't be used
// here without failing this test).
func TestTimesheetRoutes_NoDrift_CatchesUnmatrixedRoute(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)
	rec.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/throwaway-unmatrixed", func(w http.ResponseWriter, r *http.Request) {})

	missing := testsec.MissingSpecs(rec.Registered, append(testsec.Matrix{Routes: timesheetMatrixRoutes}.Patterns(), "GET /health", "GET /ready"))
	const want = "GET /api/timesheet/v1/companies/{companyId}/throwaway-unmatrixed"
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
	f := timesheetMatrixFixture(t, "")
	for _, rt := range timesheetMatrixRoutes {
		t.Run(rt.Name, func(t *testing.T) {
			rec := chaosDo(t, f, rt.Method, rt.Path, "", rt.Body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: status = %d, want 401 with no bearer", rt.Method, rt.Path, rec.Code)
			}
		})
	}
}
