// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/url"
)

// mountAdminOrgRoutes exposes org's company, org-unit and member writes on the gateway under
// `/api/org/admin/...`, superadmin-gated exactly like the position and group routes. org's own
// handlers check the bearer again with authz, so this edge adds bearer auth and the guard only.
// This is what used to be the "call the org container from inside the network" escape hatch.
func mountAdminOrgRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, orgTarget *url.URL, adminClient *AuthzAdminClient) {
	guarded := func(action string, rewrite func(*http.Request) string) http.Handler {
		return limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, action)(
			newFixedProxy(orgTarget, rewrite))))
	}
	unitByID := func(r *http.Request) string { return "/internal/org/units/" + r.PathValue("id") }
	memberByID := func(r *http.Request) string { return "/internal/org/members/" + r.PathValue("id") }

	// A company is an org unit with typeKey "company" and no parent; any other unit names its parent.
	mux.Handle("POST /api/org/admin/units", guarded("org.unit.admin_create", fixedPath("/internal/org/units")))
	mux.Handle("GET /api/org/admin/units/{id}", guarded("org.unit.admin_get", unitByID))
	mux.Handle("GET /api/org/admin/units/{id}/subtree", guarded("org.unit.admin_subtree", func(r *http.Request) string { return unitByID(r) + "/subtree" }))

	mux.Handle("POST /api/org/admin/members", guarded("org.member.admin_create", fixedPath("/internal/org/members")))
	// org's list takes the caller's kcSub like every self-scoped read; the guard already made it a superadmin.
	mux.Handle("GET /api/org/admin/members", limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "org.member.admin_list")(
		newSubjectScopedProxy(orgTarget, "/internal/org/members")))))
	mux.Handle("PUT /api/org/admin/members/{id}", guarded("org.member.admin_update", memberByID))
	mux.Handle("POST /api/org/admin/members/{id}/link-user", guarded("org.member.admin_link_user", func(r *http.Request) string { return memberByID(r) + "/link-user" }))
	mux.Handle("DELETE /api/org/admin/members/{id}/link-user", guarded("org.member.admin_unlink_user", func(r *http.Request) string { return memberByID(r) + "/link-user" }))
}
