// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// RoutesConfig bundles every dependency Routes needs: the token verifier + catalog
// client, the registry/Keycloak/admin-guard/static wiring, and the foundation routes'
// authz/org targets. RegistryBaseURL, KeycloakBaseURL, AuthzBaseURL, and OrgBaseURL must be
// absolute URLs (scheme+host) — Routes panics at construction time on a malformed one, the same
// "fail loud at startup, never serve half-built" posture NewTokenVerifier already uses for an
// unreachable JWKS endpoint. StaticDir may be empty (no frontend bundle configured yet); every
// other field is required.
type RoutesConfig struct {
	Verifier        *TokenVerifier
	Catalog         *CatalogClient
	RegistryBaseURL string
	KeycloakBaseURL string
	AdminClient     *AuthzAdminClient
	StaticDir       string
	// AuthzBaseURL/OrgBaseURL back the foundation routes (`/api/auth/...`,
	// `/api/org/me/companies`).
	AuthzBaseURL string
	OrgBaseURL   string
	// IdentityBaseURL backs first-request provisioning (Provisioner: every RequireAuth-guarded
	// route resolves a subject through identity the first time this process sees it).
	IdentityBaseURL string
	// Logger may be nil (tests); production passes the gateway's own logger (Provisioner's
	// fail-closed events).
	Logger *slog.Logger
	// KibanDomain drives the CORS allow-list (cors.go's allowedOrigins) exactly like it drives
	// TLS mode selection (cmd/gateway) and Keycloak's own frontend client web-origins
	// (internal/bootstrap/realm.go's frontendOrigins) — empty means dev-loopback origins, set
	// means the single production origin derived from it.
	KibanDomain string
	// TrustProxyHeaders makes the /auth proxy pass inbound X-Forwarded-Proto/-Host through
	// instead of self-deriving them — required (only) when TLS terminates at a trusted edge in
	// FRONT of this gateway (KIBAN_TRUSTED_PROXY; see NewAuthProxy's own comment). It also
	// decides whether inbound X-Forwarded-For is kept (clientForwardedFor) and whether
	// X-Forwarded-Proto: https earns HSTS (securityHeaders).
	TrustProxyHeaders bool
	// IssuerURL is KEYCLOAK_ISSUER_URL; its scheme+host is the public origin the Keycloak
	// proxies pin Host/X-Forwarded-* to when TrustProxyHeaders is false (NewAuthProxy's
	// publicOrigin). Empty (tests) leaves the client's Host in charge.
	IssuerURL string
	// Metrics is this process's own Prometheus registry, built once in cmd/gateway
	// via internal/obs/metrics.New("gateway", ...).EnableGatewayUpstream(). Mounted at the
	// operator-only GET /api/platform/metrics (superadmin guarded, mountPlatformRoutes), which
	// aggregates it with every other service's and enabled module's own `/metrics`
	// (metrics_aggregate.go). A nil value keeps every Registry method a documented no-op
	// (safe for tests that don't wire metrics).
	Metrics *metrics.Registry
	// DemoMode backs the `GET /api/platform/demo-mode` read — off (false) unless the
	// deploying operator explicitly sets KIBAN_DEMO_MODE=true (cmd/gateway). See
	// mountDemoModeRoute's own doc comment for why this is the smallest honest mechanism.
	DemoMode bool
}

// Routes builds the gateway's full HTTP handler: the bearer-
// protected dynamic module proxy, `/api/platform/*` (registry passthrough + the
// superadmin-guarded mutation routes), `/auth/*` (unauthenticated Keycloak reverse proxy),
// `/internal/*` (always 404 from outside), and `/` (static SPA/module-bundle serving with
// fallback). Callers (cmd/gateway) wrap the result with the shared httpx middleware
// (Correlation, Recover, AccessLog), same convention every other service uses.
func Routes(cfg RoutesConfig) http.Handler {
	mux := http.NewServeMux()

	// Dynamic, catalog-driven module proxy. Both patterns are needed: {rest...} requires
	// at least one more path segment, so a bare "/api/foo" (no trailing path) needs its own
	// exact-match registration. Neither carries a method prefix — module APIs use the full HTTP
	// verb set, and method routing is the module's own concern.
	proxy := NewModuleProxy(cfg.Catalog)
	proxy.Metrics = cfg.Metrics
	prov := NewProvisioner(cfg.IdentityBaseURL, cfg.Logger)
	protected := limitBody(moduleProxyBodyLimit, RequireAuth(cfg.Verifier, prov)(proxy))
	mux.Handle("/api/{moduleKey}", protected)
	mux.Handle("/api/{moduleKey}/{rest...}", protected)

	// `/api/platform/*`: a fixed target (the registry service), not catalog-resolved.
	// Go's stdlib ServeMux (1.22+) routes a request to the most specific matching pattern
	// regardless of registration order, so these literal-segment patterns win over the
	// `/api/{moduleKey}/{rest...}` wildcard above for the same requests without any special
	// ordering here.
	registryTarget := mustParseAbsoluteURL(cfg.RegistryBaseURL)
	aggregator := newMetricsAggregator(cfg.Metrics, map[string]string{
		"registry": cfg.RegistryBaseURL, "identity": cfg.IdentityBaseURL,
		"org": cfg.OrgBaseURL, "authz": cfg.AuthzBaseURL,
	}, cfg.Catalog)
	mountPlatformRoutes(mux, cfg.Verifier, prov, registryTarget, cfg.AdminClient, aggregator)
	mountDemoModeRoute(mux, cfg.DemoMode)

	// `/api/auth/...` + `/api/org/me/companies`: the self-facing foundation surface
	// (effective-access self can/batch-can/summary, the org company-switcher read, the
	// superadmin-guarded grant API). Same fixed-target, named-route style as the platform
	// routes above — see foundation_routes.go's package doc for the subject-injection rules.
	authzTarget := mustParseAbsoluteURL(cfg.AuthzBaseURL)
	orgTarget := mustParseAbsoluteURL(cfg.OrgBaseURL)
	mountFoundationRoutes(mux, cfg.Verifier, prov, authzTarget, orgTarget, cfg.AdminClient)

	// `/api/org/admin/...`: the sample shell's minimal position-based-access admin
	// surface (create/list/assign/end), every route superadmin-guarded.
	mountAdminPositionRoutes(mux, cfg.Verifier, prov, orgTarget, cfg.AdminClient)

	// `/api/org/admin/...`: the group admin surface (list/create groups, add/remove
	// member), the same slice pattern, same guard.
	mountAdminGroupRoutes(mux, cfg.Verifier, prov, orgTarget, cfg.AdminClient)

	// The gateway deliberately
	// mounts NO bare `GET /metrics`. Unlike every other service, the gateway's only listener IS the
	// edge — in public mode the shared Traefik forwards the whole host to it — so a bare mount here
	// was reachable unauthenticated from the internet (observed live on the demo site). The
	// gateway's own exposition is served ONLY by the operator route `GET /api/platform/metrics`
	// behind RequireSuperadmin (platform_routes.go). metrics_public_exposure_test.go pins this.

	// `/internal/*` is gateway-owned namespace that must never be reachable from outside
	// the edge, whether or not anything is mounted there. More specific than the "/"
	// catch-all below, so it always wins for this prefix.
	mux.Handle("/internal/", limitBody(defaultBodyLimit, http.HandlerFunc(writeInternalNotFound)))

	// `/auth/*`: unauthenticated reverse proxy to Keycloak (never wrapped in RequireAuth).
	keycloakTarget := mustParseAbsoluteURL(cfg.KeycloakBaseURL)
	var publicOrigin *url.URL
	if cfg.IssuerURL != "" {
		publicOrigin = mustParseAbsoluteURL(cfg.IssuerURL)
	}
	mux.Handle("/auth/", limitBody(defaultBodyLimit, NewAuthProxy(keycloakTarget, cfg.TrustProxyHeaders, publicOrigin)))

	// Keycloak's admin console/REST API (`/admin/*`) and the master realm are operator surfaces
	// (bootstrap and scripts reach Keycloak's own port directly) and must never be on the public
	// edge; nothing in the product targets them through the gateway (every SDK/shell/script URL
	// is under the app realm). More specific than `/auth/` and `/realms/` above/below, so they win.
	// keycloak_admin_exposure_test.go pins this.
	notFound := limitBody(defaultBodyLimit, http.HandlerFunc(writeInternalNotFound))
	for _, p := range []string{"/auth/admin", "/auth/admin/", "/auth/realms/master", "/auth/realms/master/", "/realms/master", "/realms/master/"} {
		mux.Handle(p, notFound)
	}

	// `/resources/*` and `/realms/*`: Keycloak-owned paths a browser can be handed
	// root-relative (no origin, so rewriteAuthOrigin's absolute-URL splice never touches them —
	// theme assets under /resources/, and /realms/ action pages like Forgot-Password). Without
	// these mounts such a request fell through to the SPA fallback below (shell HTML for a CSS/JS
	// request, or a broken Forgot-Password page). Same unauthenticated posture as /auth/*.
	verbatimProxy := limitBody(defaultBodyLimit, NewKeycloakVerbatimProxy(keycloakTarget, cfg.TrustProxyHeaders, publicOrigin))
	mux.Handle("/resources/", verbatimProxy)
	mux.Handle("/realms/", verbatimProxy)

	// `/` and everything else: static SPA/module-bundle serving with fallback.
	var static http.Handler = http.HandlerFunc(writeInternalNotFound)
	if cfg.StaticDir != "" {
		static = NewStaticHandler(cfg.StaticDir)
	}
	mux.Handle("/", limitBody(defaultBodyLimit, static))

	// CORS (cors.go's package doc has the full account)
	// wraps the ENTIRE mux, outermost, so a preflight OPTIONS (which no route above is
	// registered for — every `/api/*` pattern is method-specific) is answered directly here
	// instead of 404ing before RequireAuth is ever reached, and every actual response gets
	// `Access-Control-Allow-Origin` attached for an allowed browser Origin. securityHeaders and
	// clientForwardedFor (hardening.go) sit just inside it, so every route above — proxied or
	// gateway-written — gets the baseline security headers and the edge's own X-Forwarded-For.
	return CORS(allowedOrigins(cfg.KibanDomain))(
		securityHeaders(cfg.TrustProxyHeaders,
			clientForwardedFor(cfg.TrustProxyHeaders, mux)))
}

// routeMux is the minimal surface mountFoundationRoutes/mountAdminPositionRoutes/
// mountAdminGroupRoutes/mountPlatformRoutes need from a mux. *http.ServeMux satisfies it
// structurally (same Handle method signature), so production callers pass one unchanged;
// testsec.Recorder also satisfies it, letting the negative-security matrix mount the
// REAL production mounting function and recover the exact registered-route list it produced —
// the drift pin (internal/testsec/recorder.go's own doc comment has the full account).
type routeMux interface {
	Handle(pattern string, handler http.Handler)
}

// mustParseAbsoluteURL parses raw as an absolute (scheme+host) URL, panicking with a clear
// message if it isn't — used only at Routes construction time (process startup, or a test
// building its own Routes), never per-request.
func mustParseAbsoluteURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		panic("gateway: invalid absolute URL in config: " + raw)
	}
	return u
}
