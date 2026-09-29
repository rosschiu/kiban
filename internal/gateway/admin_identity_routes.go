// SPDX-License-Identifier: Apache-2.0

// `/api/platform/admin/mfa-policy/*` — the second-factor policy, proxied to the identity
// service's own MFA-policy routes (internal/identity/http.go). Superadmin-guarded at the edge;
// identity re-checks the forwarded bearer on every write itself (its AdminAuthorizer), so the
// guard here is defence in depth, not the only one. Users are named by Keycloak subject, the
// same id every other public route uses; identity resolves it to its own row.
package gateway

import (
	"net/http"
	"net/url"
)

func mountAdminIdentityRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, identityTarget *url.URL, adminClient *AuthzAdminClient) {
	guarded := func(action string, rewrite func(*http.Request) string) http.Handler {
		return limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, action)(
			newFixedProxy(identityTarget, rewrite))))
	}
	bySubject := func(r *http.Request) string {
		return "/internal/identity/mfa-policy/subjects/" + r.PathValue("subject")
	}

	mux.Handle("GET /api/platform/admin/mfa-policy/global", guarded("identity.mfa_policy.read", fixedPath("/internal/identity/mfa-policy/global")))
	mux.Handle("PUT /api/platform/admin/mfa-policy/global", guarded("identity.mfa_policy.set_global", fixedPath("/internal/identity/mfa-policy/global")))
	mux.Handle("GET /api/platform/admin/mfa-policy/users/{subject}", guarded("identity.mfa_policy.read", bySubject))
	mux.Handle("PUT /api/platform/admin/mfa-policy/users/{subject}", guarded("identity.mfa_policy.set_user", bySubject))
	mux.Handle("DELETE /api/platform/admin/mfa-policy/users/{subject}", guarded("identity.mfa_policy.clear_user", bySubject))
	mux.Handle("POST /api/platform/admin/mfa-policy/sync", guarded("identity.mfa_policy.sync", fixedPath("/internal/identity/mfa-policy/sync")))
}
