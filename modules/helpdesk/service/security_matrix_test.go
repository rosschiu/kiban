// SPDX-License-Identifier: Apache-2.0

// The shared negative-security matrix (internal/testsec), retrofitted to
// every route in this module's own route table (http.go's mountRoutes). Drift-pinned per the
// same pattern as modules/timesheet/service/security_matrix_test.go.
package helpdesk

import (
	"net/http"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/testchaos"
	"github.com/rosschiu/kiban/internal/testsec"
)

// helpdeskMatrixCompanyID/TicketID are fixed sample UUIDs — helpdesk's own withAuth parses
// companyId (and, when present, ticketId) as a UUID BEFORE the authz.Can call, so every route
// needs a syntactically-valid UUID in path position even for the guard-level assertions this
// matrix runs (none of which ever reach the handler itself).
const (
	helpdeskMatrixCompanyID = "11111111-1111-1111-1111-111111111111"
	helpdeskMatrixTicketID  = "22222222-2222-2222-2222-222222222222"
	helpdeskMatrixMemberID  = "33333333-3333-3333-3333-333333333333"
)

var helpdeskMatrixRoutes = []testsec.RouteSpec{
	{Name: "my_tier", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/me", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/me"},
	{Name: "list_tickets", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/tickets", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets"},
	{Name: "create_ticket", Pattern: "POST /api/helpdesk/v1/companies/{companyId}/tickets", Method: http.MethodPost, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets", Body: `{}`},
	{Name: "get_ticket", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID},
	{Name: "get_ticket_audit", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/audit", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID + "/audit"},
	{Name: "assign_ticket", Pattern: "POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/assign", Method: http.MethodPost, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID + "/assign", Body: `{}`},
	{Name: "transition_status", Pattern: "POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/status", Method: http.MethodPost, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID + "/status", Body: `{}`},
	{Name: "list_comments", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/comments", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID + "/comments"},
	{Name: "create_comment", Pattern: "POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/comments", Method: http.MethodPost, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/tickets/" + helpdeskMatrixTicketID + "/comments", Body: `{}`},
	{Name: "assignable_positions", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/assignable-positions", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/assignable-positions"},
	{Name: "assignable_groups", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/assignable-groups", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/assignable-groups"},
	{Name: "list_agents", Pattern: "GET /api/helpdesk/v1/companies/{companyId}/agents", Method: http.MethodGet, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/agents"},
	{Name: "make_agent", Pattern: "POST /api/helpdesk/v1/companies/{companyId}/agents", Method: http.MethodPost, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/agents", Body: `{}`},
	{Name: "remove_agent_position", Pattern: "DELETE /api/helpdesk/v1/companies/{companyId}/agents/positions/{positionId}", Method: http.MethodDelete, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/agents/positions/" + helpdeskMatrixMemberID},
	{Name: "remove_agent_group", Pattern: "DELETE /api/helpdesk/v1/companies/{companyId}/agents/groups/{groupId}", Method: http.MethodDelete, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/agents/groups/" + helpdeskMatrixMemberID},
	{Name: "remove_agent", Pattern: "DELETE /api/helpdesk/v1/companies/{companyId}/agents/{memberId}", Method: http.MethodDelete, Path: "/api/helpdesk/v1/companies/" + helpdeskMatrixCompanyID + "/agents/" + helpdeskMatrixMemberID},
}

func TestHelpdeskRoutes_NegativeSecurityMatrix(t *testing.T) {
	m := testsec.Matrix{
		Routes: helpdeskMatrixRoutes,
		Allowed: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil, nil, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		Forbidden: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil, nil, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-nobody")}
		},
		Unavailable: func(t *testing.T) testsec.Fixture {
			org := newFakeOrg(t, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newHDChaosFixture(t, testchaos.RefusedURL(), org.url, notifSrv.URL, 300*time.Millisecond)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		// See timesheet's own matrix file for why this is the module-shape forged-header proof:
		// helpdesk's withAuth never reads an inbound x-user-*/x-kiban-* header.
		ForgedHeaders: map[string]string{"X-User-Id": "spoofed-admin", "X-Kiban-Role": "kiban-superadmin"},
		ForgedBearer:  "",
		ForgedWant:    http.StatusUnauthorized,
	}
	m.Run(t)
}

func TestHelpdeskRoutes_NoDrift(t *testing.T) {
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
	testsec.AssertNoDrift(t, registered, testsec.Matrix{Routes: helpdeskMatrixRoutes}.Patterns())
}

func TestHelpdeskRoutes_NoDrift_CatchesUnmatrixedRoute(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)
	rec.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/throwaway-unmatrixed", func(w http.ResponseWriter, r *http.Request) {})

	missing := testsec.MissingSpecs(rec.Registered, append(testsec.Matrix{Routes: helpdeskMatrixRoutes}.Patterns(), "GET /health", "GET /ready"))
	const want = "GET /api/helpdesk/v1/companies/{companyId}/throwaway-unmatrixed"
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
	f := newHTTPFixture(t, nil, nil, nil)
	for _, rt := range helpdeskMatrixRoutes {
		t.Run(rt.Name, func(t *testing.T) {
			rec := f.do(t, rt.Method, rt.Path, "", rt.Body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: status = %d, want 401 with no bearer", rt.Method, rt.Path, rec.Code)
			}
		})
	}
}
