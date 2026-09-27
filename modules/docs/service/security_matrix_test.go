// SPDX-License-Identifier: Apache-2.0

// The shared negative-security matrix (internal/testsec), retrofitted to
// every route in this module's own route table (http.go's mountRoutes) — both the feature-gated
// withAuth routes (documents list/create, module audit) and the per-document withObjectAuth
// routes (get/update/delete document, shares, document audit). Drift-pinned per the same pattern
// as modules/timesheet/service/security_matrix_test.go.
package docs

import (
	"net/http"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/testchaos"
	"github.com/rosschiu/kiban/internal/testsec"
)

// docsMatrixCompanyID/DocID/MemberID are fixed sample UUIDs — docs's own withAuth/withObjectAuth
// parse companyId (and, for object routes, docId) as a UUID BEFORE the authz check, so every
// route needs a syntactically-valid UUID in path position even for the guard-level assertions
// this matrix runs.
const (
	docsMatrixCompanyID = "11111111-1111-1111-1111-111111111111"
	docsMatrixDocID     = "22222222-2222-2222-2222-222222222222"
	docsMatrixMemberID  = "33333333-3333-3333-3333-333333333333"
)

var docsMatrixRoutes = []testsec.RouteSpec{
	{Name: "list_documents", Pattern: "GET /api/docs/v1/companies/{companyId}/documents", Method: http.MethodGet, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents"},
	{Name: "create_document", Pattern: "POST /api/docs/v1/companies/{companyId}/documents", Method: http.MethodPost, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents", Body: `{"title":"t"}`},
	{Name: "get_document", Pattern: "GET /api/docs/v1/companies/{companyId}/documents/{docId}", Method: http.MethodGet, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID},
	{Name: "update_document", Pattern: "PUT /api/docs/v1/companies/{companyId}/documents/{docId}", Method: http.MethodPut, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID, Body: `{}`},
	{Name: "delete_document", Pattern: "DELETE /api/docs/v1/companies/{companyId}/documents/{docId}", Method: http.MethodDelete, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID},
	{Name: "list_shares", Pattern: "GET /api/docs/v1/companies/{companyId}/documents/{docId}/shares", Method: http.MethodGet, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID + "/shares"},
	{Name: "create_share", Pattern: "POST /api/docs/v1/companies/{companyId}/documents/{docId}/shares", Method: http.MethodPost, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID + "/shares", Body: `{"memberId":"` + docsMatrixMemberID + `"}`},
	{Name: "revoke_share", Pattern: "DELETE /api/docs/v1/companies/{companyId}/documents/{docId}/shares/{memberId}", Method: http.MethodDelete, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID + "/shares/" + docsMatrixMemberID},
	{Name: "get_document_audit", Pattern: "GET /api/docs/v1/companies/{companyId}/documents/{docId}/audit", Method: http.MethodGet, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/documents/" + docsMatrixDocID + "/audit"},
	{Name: "get_module_audit", Pattern: "GET /api/docs/v1/companies/{companyId}/audit", Method: http.MethodGet, Path: "/api/docs/v1/companies/" + docsMatrixCompanyID + "/audit"},
}

func TestDocsRoutes_NegativeSecurityMatrix(t *testing.T) {
	m := testsec.Matrix{
		Routes: docsMatrixRoutes,
		Allowed: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil, nil, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		Forbidden: func(t *testing.T) testsec.Fixture {
			f := newHTTPFixture(t, nil, nil, nil)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-nobody")}
		},
		Unavailable: func(t *testing.T) testsec.Fixture {
			orgSrv := newFakeOrg(t, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newChaosFixture(t, testchaos.RefusedURL(), orgSrv.URL, notifSrv.URL, 300*time.Millisecond)
			return testsec.Fixture{Handler: f.handler, Bearer: f.token(t, "kcsub-someone")}
		},
		// See timesheet's own matrix file for why this is the module-shape forged-header proof:
		// docs's withAuth/withObjectAuth never read an inbound x-user-*/x-kiban-* header.
		ForgedHeaders: map[string]string{"X-User-Id": "spoofed-admin", "X-Kiban-Role": "kiban-superadmin"},
		ForgedBearer:  "",
		ForgedWant:    http.StatusUnauthorized,
	}
	m.Run(t)
}

func TestDocsRoutes_NoDrift(t *testing.T) {
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
	testsec.AssertNoDrift(t, registered, testsec.Matrix{Routes: docsMatrixRoutes}.Patterns())
}

func TestDocsRoutes_NoDrift_CatchesUnmatrixedRoute(t *testing.T) {
	svc := &Service{}
	rec := testsec.NewRecorder()
	svc.mountRoutes(rec)
	rec.HandleFunc("GET /api/docs/v1/companies/{companyId}/throwaway-unmatrixed", func(w http.ResponseWriter, r *http.Request) {})

	missing := testsec.MissingSpecs(rec.Registered, append(testsec.Matrix{Routes: docsMatrixRoutes}.Patterns(), "GET /health", "GET /ready"))
	const want = "GET /api/docs/v1/companies/{companyId}/throwaway-unmatrixed"
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
	for _, rt := range docsMatrixRoutes {
		t.Run(rt.Name, func(t *testing.T) {
			rec := f.do(t, rt.Method, rt.Path, "", rt.Body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: status = %d, want 401 with no bearer", rt.Method, rt.Path, rec.Code)
			}
		})
	}
}
