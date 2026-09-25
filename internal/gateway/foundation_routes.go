// SPDX-License-Identifier: Apache-2.0

// The self-facing foundation API surface — effective access for the CALLER, the
// caller's org context, and the admin grant path — mounted at the edge, named-route style
// (platform_routes.go's own pattern), never a generic `/internal/*` passthrough.
//
// Subject-injection rule: a caller
// may only ever ask about THEIR OWN access. Two different mechanisms enforce that here, matching
// what each downstream endpoint already expects:
//   - `can`/`batch-can`/`grants` (internal/authz/http.go) validate the bearer THEMSELVES and
//     already reject a body `actorId` that doesn't match the bearer subject (400) — these three
//     routes are plain fixed-target proxies (newFixedProxy, reused from platform_routes.go) that
//     add nothing beyond bearer-gating at the edge; the real subject enforcement lives downstream
//     and is exercised end to end through this proxy (TestEffectiveAccessCan_BodySubjectRejected
//     etc.), never re-implemented here (that would risk drifting from authz's own rule).
//   - `summary`/`me/companies` (internal/authz/summary.go, internal/org/http.go) are
//     internal-network-only reads that take kcSub as a plain, UNAUTHENTICATED query param (the
//     same shape as org's company-facts read) — the gateway is the
//     bearer-validating boundary for both, and newSubjectScopedProxy is what injects the
//     validated bearer's own kcSub into the outbound query, overwriting (never trusting) any
//     client-supplied kcSub.
package gateway

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// fixedPath returns a rewritePath func (newFixedProxy's second argument) that always rewrites to
// the same outbound path, ignoring the inbound request entirely — the shape every route in this
// file needs since each is a named, single-purpose mount (not a wildcard/parameterized proxy).
func fixedPath(path string) func(*http.Request) string {
	return func(*http.Request) string { return path }
}

// newSubjectScopedProxy builds a reverse proxy to target that rewrites the outbound path to
// internalPath and forces the outbound query's "kcSub" to the validated bearer's own subject
// (AuthFromContext, attached by RequireAuth upstream of this handler) — any client-supplied
// "kcSub" in the inbound query is overwritten, never forwarded. Every other inbound query param
// (e.g. summary's "companyId") passes through unchanged: companyId scopes the query, it does not
// name a subject, so it carries no enforcement-boundary risk (the rule is about not forwarding
// a client-supplied identity, not about query params in general).
func newSubjectScopedProxy(target *url.URL, internalPath string) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			pr.Out.URL.Path = internalPath
			pr.Out.URL.RawPath = ""

			authCtx, _ := AuthFromContext(pr.In.Context())
			q := pr.In.URL.Query()
			q.Set("kcSub", authCtx.Subject)
			pr.Out.URL.RawQuery = q.Encode()
			copyForwardedFor(pr)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProxyError(w, err, "foundation service unreachable")
		},
	}
}

// newMemberDirectoryProxy builds the proxy for `GET /api/org/companies/{companyId}/
// members`: rewrites the outbound path to org's internal member-directory route using the
// inbound request's OWN {companyId} path value (never client-controlled beyond that — the path
// segment is the same one RequireAuth's downstream handler already matched on), and — exactly
// like newSubjectScopedProxy above — forces the outbound "kcSub" query param to the validated
// bearer's own subject, overwriting any client-supplied value. "q"/"page"/"pageSize" pass
// through unchanged (query scoping, not identity, per newSubjectScopedProxy's own doc comment).
func newMemberDirectoryProxy(target *url.URL) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			pr.Out.URL.Path = "/internal/org/companies/" + pr.In.PathValue("companyId") + "/members"
			pr.Out.URL.RawPath = ""

			authCtx, _ := AuthFromContext(pr.In.Context())
			q := pr.In.URL.Query()
			q.Set("kcSub", authCtx.Subject)
			pr.Out.URL.RawQuery = q.Encode()
			copyForwardedFor(pr)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProxyError(w, err, "foundation service unreachable")
		},
	}
}

// mountFoundationRoutes registers the `/api/auth/...` + `/api/org/...` foundation routes on
// mux: self-scoped effective-access can/batch-can/summary, the org company-switcher read, the
// member directory read, the superadmin-guarded grant API and the superadmin-guarded platform-
// role grant/revoke (`/api/platform/admin/platform-roles`). Every route requires a validated
// bearer (RequireAuth); grants and platform-roles additionally require the superadmin guard.
func mountFoundationRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, authzTarget, orgTarget *url.URL, adminClient *AuthzAdminClient) {
	authed := func(h http.Handler) http.Handler {
		return limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(h))
	}

	mux.Handle("POST /api/auth/effective-access/can", authed(
		newFixedProxy(authzTarget, fixedPath("/internal/authz/effective-access/can"))))
	mux.Handle("POST /api/auth/effective-access/batch-can", authed(
		newFixedProxy(authzTarget, fixedPath("/internal/authz/effective-access/batch-can"))))
	mux.Handle("GET /api/auth/effective-access/summary", authed(
		newSubjectScopedProxy(authzTarget, "/internal/authz/effective-access/summary")))

	mux.Handle("GET /api/org/me/companies", authed(
		newSubjectScopedProxy(orgTarget, "/internal/org/me/companies")))

	// The browser-reachable, authorized company member directory (share-with/
	// assign-to picker) — org's own handler enforces the ACTIVE-membership-or-superadmin
	// gate (internal/org/http.go's requireMemberOrAdmin); this route's own job is only bearer
	// auth + kcSub injection, same division of labor as summary/me-companies above.
	mux.Handle("GET /api/org/companies/{companyId}/members", authed(newMemberDirectoryProxy(orgTarget)))

	mux.Handle("POST /api/auth/grants", limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "authz.grants.write")(
		newFixedProxy(authzTarget, fixedPath("/internal/authz/grants"))))))

	// The platform role's grant/revoke — authz owns the role's one record (the
	// `system:platform#superadmin` tuple) and its rules (last superadmin ⇒ 409); this edge adds
	// only bearer auth + the superadmin guard, exactly like grants above.
	mux.Handle("POST /api/platform/admin/platform-roles", limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "authz.platform_role.grant")(
		newFixedProxy(authzTarget, fixedPath("/internal/authz/platform-roles"))))))
	mux.Handle("DELETE /api/platform/admin/platform-roles/{role}/{subjectId}", limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "authz.platform_role.revoke")(
		newFixedProxy(authzTarget, func(r *http.Request) string {
			return "/internal/authz/platform-roles/" + r.PathValue("role") + "/" + r.PathValue("subjectId")
		})))))
}
