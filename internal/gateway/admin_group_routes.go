// SPDX-License-Identifier: Apache-2.0

// The sample shell's minimal group admin surface — the position admin slice pattern
// applied to groups. Four browser-reachable org WRITE routes, ALL behind the existing
// superadmin (superadmin) guard: list/create groups, add/remove a group member. Fixed
// proxies to org's own internal routes; the real authorization/validation (INCLUDING
// the single-writer invariant's 409 GROUP_EXTERNALLY_MANAGED) lives downstream in org's own
// handlers — this file adds nothing beyond path rewriting + the guard, same posture as
// admin_position_routes.go.
package gateway

import (
	"net/http"
	"net/url"
)

// rewriteAdminCompanyGroupsPath rewrites both the list (GET) and create (POST) admin routes to
// org's own `/internal/org/companies/{id}/groups` — the inbound request's OWN {companyId} path
// value is the only company identity this route ever trusts (never a body value; org's own
// handleAdminCreateGroup independently rejects a body companyId with 422).
func rewriteAdminCompanyGroupsPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/companies/" + r.PathValue("companyId") + "/groups"
	}
}

// rewriteAdminGroupMembersPath rewrites the add-member admin route to org's existing
// `/internal/org/groups/{id}/members`.
func rewriteAdminGroupMembersPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/groups/" + r.PathValue("id") + "/members"
	}
}

// rewriteAdminGroupMemberPath rewrites the remove-member admin route to org's existing
// `/internal/org/groups/{id}/members/{memberId}`.
func rewriteAdminGroupMemberPath() func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/org/groups/" + r.PathValue("id") + "/members/" + r.PathValue("memberId")
	}
}

// mountAdminGroupRoutes registers the four `/api/org/admin/*` group routes on mux, every one
// gated by RequireAuth AND RequireSuperadmin — same fail-closed shape
// mountAdminPositionRoutes already established. orgTarget is org's compose-internal base URL.
func mountAdminGroupRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, orgTarget *url.URL, adminClient *AuthzAdminClient) {
	guarded := func(action string, rewrite func(*http.Request) string) http.Handler {
		return limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, action)(
			newFixedProxy(orgTarget, rewrite))))
	}

	mux.Handle("GET /api/org/admin/companies/{companyId}/groups",
		guarded("org.group.admin_list", rewriteAdminCompanyGroupsPath()))
	mux.Handle("POST /api/org/admin/companies/{companyId}/groups",
		guarded("org.group.admin_create", rewriteAdminCompanyGroupsPath()))
	// GET .../groups/{id}/members: the Groups admin page needs to list a group's CURRENT members
	// (to render a remove button per member) — org's own internal read
	// (GET /internal/org/groups/{id}/members) already exists; this is its
	// superadmin-gated browser exposure, same posture as the list/create routes above.
	mux.Handle("GET /api/org/admin/groups/{id}/members",
		guarded("org.group.admin_member_list", rewriteAdminGroupMembersPath()))
	mux.Handle("POST /api/org/admin/groups/{id}/members",
		guarded("org.group.admin_member_add", rewriteAdminGroupMembersPath()))
	mux.Handle("DELETE /api/org/admin/groups/{id}/members/{memberId}",
		guarded("org.group.admin_member_remove", rewriteAdminGroupMemberPath()))
}
