// SPDX-License-Identifier: Apache-2.0

// CORS handling for the gateway. Every `/api/*` route is bearer-authenticated with a
// custom `Authorization` header, which makes every cross-origin browser call a "not simple"
// request — the browser sends a preflight `OPTIONS` first, and refuses to expose the real
// response to page JS unless the response carries `Access-Control-Allow-Origin` (matching the
// page's own origin). Without this every post-login `/api/*` fetch from a dev-server origin
// fails with "Failed to fetch" / a CORS console error. RequireAuth
// itself is untouched — this only adds the response headers a compliant browser requires to
// read an otherwise-identical response; it never changes who is authenticated or authorized.
//
// allowedOrigins mirrors internal/bootstrap/realm.go's frontendOrigins EXACTLY (same KIBAN_DOMAIN
// empty/set branching, same literal dev-loopback origins) — the Keycloak client's own
// `webOrigins` already trusts this exact origin set (confirmed live: a real access token minted
// for kiban-frontend carries `"allowed-origins":["http://localhost","http://localhost:3000",
// "http://localhost:5173"]`), so the gateway's CORS policy stays consistent with the identity
// provider's own trust boundary rather than inventing a separate one. Not shared as an import
// (internal/bootstrap importing into internal/gateway, or vice versa, would be a new
// cross-service dependency) — three literal strings duplicated once, the same "small,
// deliberately duplicated helper" convention this codebase uses elsewhere.
package gateway

import (
	"net/http"
)

// allowedOrigins returns the CORS-trusted origins for kibanDomain: the same dev-loopback set
// bootstrap's frontendOrigins uses when KIBAN_DOMAIN is unset, else the single production
// origin derived from KIBAN_DOMAIN.
func allowedOrigins(kibanDomain string) []string {
	if kibanDomain == "" {
		return []string{"http://localhost:3000", "http://localhost:5173", "http://localhost"}
	}
	return []string{"https://" + kibanDomain}
}

// corsAllowedHeaders/corsAllowedMethods are the request headers/methods this API surface
// actually uses — Authorization (the bearer), Content-Type (JSON bodies), x-correlation-id
// (client.ts sets it on every call).
const corsAllowedHeaders = "Authorization, Content-Type, x-correlation-id"
const corsAllowedMethods = "GET, POST, PUT, DELETE, OPTIONS"

// The Keycloak mounts (`/auth/*`, and the verbatim `/realms/*` + `/resources/*` —
// hardening.go's keycloakPrefixes) are exempt: Keycloak already answers CORS itself there (it
// has its own `webOrigins`-driven policy, confirmed live: the gateway's own /auth-proxied token
// endpoint already returns a correct, single `Access-Control-Allow-Origin`). Wrapping the WHOLE
// mux (routes.go's own comment explains why: preflight OPTIONS needs to be caught before
// ServeMux's method-specific routing 404s/405s it) would otherwise duplicate that header on
// those responses — two values on one header is itself a CORS failure (a browser treats a
// multi-valued Access-Control-Allow-Origin as invalid), which is exactly the bug this
// exemption fixes.

// CORS wraps next with cross-origin support for every request under `/api/*` (the Keycloak
// mounts are exempt — see above): an allowed Origin gets `Access-Control-Allow-
// Origin` echoed back (plus `Vary: Origin`, since the response depends on the request's Origin)
// on every response, and a browser preflight (`OPTIONS` with an Origin header) is answered
// directly with 204 — never forwarded to next, since next's routes are method-specific (`GET
// /api/...`, `POST /api/...`) and a preflight's OPTIONS verb would otherwise 404/405 before
// RequireAuth is ever reached. An Origin outside allowed is left with no CORS headers at all
// (the browser then enforces its own same-origin default — no explicit rejection needed here);
// a request with no Origin header (same-origin browser navigation, or any non-browser caller:
// curl, another service) passes through untouched.
func CORS(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || !allowed[origin] || hasKeycloakPrefix(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", corsAllowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowedHeaders)
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
