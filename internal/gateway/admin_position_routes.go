// SPDX-License-Identifier: Apache-2.0

// The sample shell's minimal position-based-access admin surface —
// four browser-reachable org WRITE routes, ALL behind the existing superadmin (superadmin)
// guard. Fixed proxies to org's internal routes, same newFixedProxy pattern platform_routes.go/
// foundation_routes.go already use for their own admin surfaces — this file adds nothing beyond
// path rewriting + the guard; the real authorization/validation lives downstream in org's own
// handlers (handleAdminCreatePosition/handleAssignNow/handleEndAssignment all call
// svc.authorize themselves — defense in depth with the gateway's own guard, same double-check
// shape org's other routes already have when reached through this gateway).
//
// NOT exposed here: org-unit CRUD, member CRUD, position
// update/delete, identity/MFA admin — this file mounts exactly these four routes,
// nothing else.
package gateway

import (
	"net/http"
	"net/url"
)

// rewriteAdminCompanyPositionsPath rewrites both the list (GET) and create (POST) admin routes
// to org's own `/internal/org/companies/{id}/positions` — the inbound request's OWN {companyId}
// path value is the only company identity this route ever trusts (never a body value; org's own
// handleAdminCreatePosition independently rejects a body companyId/orgUnitId with 422).
func rewriteAdminCompanyPositionsPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/companies/" + r.PathValue("companyId") + "/positions"
	}
}

// rewriteAdminPositionAssignmentsPath rewrites the assign-now admin route to org's existing
// `/internal/org/positions/{id}/assignments` — company is derived from the position
// server-side, never supplied by the caller.
func rewriteAdminPositionAssignmentsPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/positions/" + r.PathValue("id") + "/assignments"
	}
}

// rewriteAdminAssignmentEndPath rewrites the end-now admin route to org's existing
// `/internal/org/assignments/{id}/end` — no body is read on either side (server-dated).
func rewriteAdminAssignmentEndPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/assignments/" + r.PathValue("id") + "/end"
	}
}

// mountAdminPositionRoutes registers the four `/api/org/admin/*` routes on mux,
// every one gated by RequireAuth (bearer, and the forged x-user-* rejection RequireAuth already
// does for every /api/* route) AND RequireSuperadmin (fail-closed superadmin guard — a
// downstream authz outage is 503, never a silent allow). orgTarget is org's compose-internal
// base URL.
func mountAdminPositionRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, orgTarget *url.URL, adminClient *AuthzAdminClient) {
	guarded := func(action string, rewrite func(*http.Request) string) http.Handler {
		return limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, action)(
			newFixedProxy(orgTarget, rewrite))))
	}

	mux.Handle("GET /api/org/admin/companies/{companyId}/positions",
		guarded("org.position.admin_list", rewriteAdminCompanyPositionsPath()))
	mux.Handle("POST /api/org/admin/companies/{companyId}/positions",
		guarded("org.position.admin_create", rewriteAdminCompanyPositionsPath()))
	mux.Handle("POST /api/org/admin/positions/{id}/assignments",
		guarded("org.assignment.admin_create", rewriteAdminPositionAssignmentsPath()))
	mux.Handle("POST /api/org/admin/assignments/{id}/end",
		guarded("org.assignment.admin_end", rewriteAdminAssignmentEndPath()))
}
