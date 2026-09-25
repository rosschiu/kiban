// SPDX-License-Identifier: Apache-2.0

// `/api/platform/*` — routed to the registry service, NOT the dynamic catalog-driven
// module proxy (proxy.go). Catalog/capability reads pass through WITHOUT the admin
// gate (deliberate, avoids the gateway<->authz cycle); registry mutations are proxied under
// `/api/platform/admin/*` and DO require the superadmin guard.
package gateway

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/rosschiu/kiban/internal/errenv"
)

// newFixedProxy builds a reverse proxy to a single fixed target (unlike proxy.go's ModuleProxy,
// which resolves its target per-request from the catalog snapshot). rewritePath, when non-nil,
// replaces the outbound path (used for the admin routes below, which are gateway-owned paths
// distinct from the registry's own internal route names — the "never parse/rewrite module API
// paths" rule is about the module-key dynamic proxy's version-blindness, not about the
// gateway's own fixed `/api/platform/*` surface). A nil
// rewritePath forwards the inbound path unchanged (the catalog/capability passthrough routes,
// whose paths already match the registry's own).
func newFixedProxy(target *url.URL, rewritePath func(*http.Request) string) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			if rewritePath != nil {
				pr.Out.URL.Path = rewritePath(pr.In)
				pr.Out.URL.RawPath = ""
			}
			copyForwardedFor(pr)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProxyError(w, err, "platform registry unreachable")
		},
	}
}

// rewriteAdminModulePath maps the gateway's public `/api/platform/admin/modules/{key}/<action>`
// path to the registry's own existing mutation route,
// `/internal/platform/modules/{key}/<action>` (internal/registry/http.go) — the registry ships
// no route under `/api/platform/admin/*` itself; that public surface is the gateway's, wired
// once here for the two mutations the registry actually has (enable/disable).
func rewriteAdminModulePath(action string) func(*http.Request) string {
	return func(r *http.Request) string {
		return "/internal/platform/modules/" + r.PathValue("key") + "/" + action
	}
}

// mountPlatformRoutes registers `/api/platform/*` on mux: capability/catalog reads behind
// standard bearer auth only, admin mutations behind bearer auth AND the superadmin guard.
// metricsHandler serves the operator metrics route (`GET /api/platform/metrics` below) — the
// aggregated exposition (metrics_aggregate.go); nil mounts a 404 there.
func mountPlatformRoutes(mux routeMux, verifier *TokenVerifier, prov *Provisioner, registryTarget *url.URL, adminClient *AuthzAdminClient, metricsHandler http.Handler) {
	passthrough := limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(newFixedProxy(registryTarget, nil)))
	mux.Handle("GET /api/platform/capabilities", passthrough)
	mux.Handle("GET /api/platform/capabilities/{module}", passthrough)
	mux.Handle("GET /api/platform/catalog", passthrough)

	enable := limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "registry.modules.enable")(
		newFixedProxy(registryTarget, rewriteAdminModulePath("enable")))))
	disable := limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(RequireSuperadmin(adminClient, "registry.modules.disable")(
		newFixedProxy(registryTarget, rewriteAdminModulePath("disable")))))
	mux.Handle("POST /api/platform/admin/modules/{key}/enable", enable)
	mux.Handle("POST /api/platform/admin/modules/{key}/disable", disable)

	// `GET /api/platform/metrics` — the ONE operator-facing metrics surface exposed through
	// the gateway: the platform-wide aggregated exposition (metrics_aggregate.go — the
	// gateway's own registry plus every service's and enabled module's `/metrics`, each series
	// labeled `service`), behind the same superadmin guard every other `/api/platform/admin/*`
	// mutation uses. The bare per-service `/metrics` listeners stay internal-network only.
	if metricsHandler == nil {
		metricsHandler = http.NotFoundHandler()
	}
	mux.Handle("GET /api/platform/metrics", limitBody(defaultBodyLimit, RequireAuth(verifier, prov)(
		RequireSuperadmin(adminClient, "platform.metrics.read")(metricsHandler))))
}

// mountDemoModeRoute registers `GET /api/platform/demo-mode` — the deployment-flag
// read for the shell's demo banner. Deliberately the smallest honest mechanism given the
// gateway already serves the SPA bundle: one build/deploy-time env var (KIBAN_DEMO_MODE,
// cmd/gateway) threaded straight through to this static, UNAUTHENTICATED read — no registry
// round trip, no new DB row, no per-request state. Unauthenticated because "is this deployment
// the public demo" carries no more sensitivity than the SPA bundle itself (a logged-out visitor
// sees the banner before ever logging in); every other `/api/platform/*` route's RequireAuth
// gate exists to protect ACTUAL platform data, which this endpoint has none of. Off (false)
// unless the deploying operator explicitly sets KIBAN_DEMO_MODE=true — never inferred from
// KibanDomain/hostname, so a copy of the compose file never accidentally turns the banner on
// for a non-demo deployment.
func mountDemoModeRoute(mux routeMux, demoMode bool) {
	mux.Handle("GET /api/platform/demo-mode", limitBody(defaultBodyLimit, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			errenv.WriteData(w, http.StatusOK, map[string]bool{"enabled": demoMode})
		},
	)))
}
