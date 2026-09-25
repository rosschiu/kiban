// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// defaultModuleHost is the backend host every foundation service and module binds to when
// host-run: 127.0.0.1 (every published port is localhost-only; the gateway terminates the edge).
// The registry's catalog carries a port but no host field at all (the module manifest has none
// either), so per-module host resolution is the gateway's OWN config, not a registry schema
// concern. KIBAN_MODULE_HOST_<MODULEKEY> (uppercased) overrides the default per module — compose
// and Kubernetes wiring set it to the module's service name, and tests use it to point a module
// at an httptest server on a non-default host.
const defaultModuleHost = "127.0.0.1"

func moduleHost(moduleKey string) string {
	if v := os.Getenv("KIBAN_MODULE_HOST_" + strings.ToUpper(moduleKey)); v != "" {
		return v
	}
	return defaultModuleHost
}

// Upstream transport timeouts: the gateway server's own WriteTimeout (cmd/gateway/main.go's 10s)
// would otherwise be the only thing bounding a hung module upstream — implicit, and shared across
// the whole gateway process rather than scoped to the module proxy specifically. These two make
// the bound explicit at the proxy transport itself,
// well under that 10s backstop so the proxy's own error handling (503 MODULE_UNAVAILABLE, the
// same code TestProxy_Unreachable503 already proves for connection-refused) fires first, with
// room to spare, rather than racing the server's hard cutoff. Both are configurable via env
// (KIBAN_MODULE_DIAL_TIMEOUT / KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT, Go duration syntax) for
// ops tuning and so tests can shrink them, mirroring KIBAN_MODULE_HOST_* above.
const (
	defaultModuleDialTimeout           = 2 * time.Second
	defaultModuleResponseHeaderTimeout = 5 * time.Second
)

func durationEnv(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// newModuleTransport builds the ONE *http.Transport a ModuleProxy uses for every upstream
// request (built once in NewModuleProxy, never per request): keep-alive on, a bounded idle pool
// per upstream, idle connections reaped after 90 s. A per-request transport would leave each
// keep-alive connection and its two loop goroutines alive until the upstream closed them.
func newModuleTransport() *http.Transport {
	dialTimeout := durationEnv("KIBAN_MODULE_DIAL_TIMEOUT", defaultModuleDialTimeout)
	responseHeaderTimeout := durationEnv("KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT", defaultModuleResponseHeaderTimeout)
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
		ResponseHeaderTimeout: responseHeaderTimeout,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}
}

// ModuleProxy resolves /api/:moduleKey/* against the registry's catalog snapshot, enforces the
// three capability codes in their canonical order
// (MODULE_NOT_INSTALLED -> MODULE_DISABLED -> MODULE_DEPENDENCY_MISSING, exact order), and —
// only once a module is fully ready — forwards the request opaquely (the gateway never
// parses/rewrites anything past the module key) to the module's registered host:port.
type ModuleProxy struct {
	Catalog *CatalogClient
	// Metrics records kiban_gateway_upstream_requests_total/duration_seconds{module,status} per
	// proxied request. Nil-safe — RecordGatewayUpstream on a nil *metrics.Registry is
	// a documented no-op, so leaving this unset (every existing test's NewModuleProxy call) keeps
	// working unchanged.
	Metrics *metrics.Registry

	// transport is the single shared upstream transport (newModuleTransport) — set by
	// NewModuleProxy; tests may swap its DialContext before the first request.
	transport *http.Transport
}

// NewModuleProxy builds a ModuleProxy against the given catalog client. Metrics is left unset
// (nil) — set it on the returned value when a Registry is available (cmd/gateway wires it via
// RoutesConfig.Metrics).
func NewModuleProxy(catalog *CatalogClient) *ModuleProxy {
	return &ModuleProxy{Catalog: catalog, transport: newModuleTransport()}
}

// ServeHTTP implements the /api/{moduleKey}/{rest...} (and bare /api/{moduleKey}) handler wired
// in cmd/gateway. moduleKey comes from r.PathValue (stdlib 1.22+ pattern routing) —
// the {rest...} wildcard match itself is never consulted or reconstructed from; forwarding
// always uses the ORIGINAL, untouched request URL (see rewrite below), so opaqueness holds even
// for adversarial segments like an encoded slash.
func (p *ModuleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	moduleKey := r.PathValue("moduleKey")

	snapshot, err := p.Catalog.Get(r.Context())
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
			Code:    errenv.CodeModuleUnavailable,
			Message: "module catalog unavailable",
		})
		return
	}

	entry, ok := snapshot.Lookup(moduleKey)
	if !ok {
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
			Code:    errenv.CodeNotFound,
			Message: "unknown module",
		})
		return
	}

	// Canonical 3-code order, re-checked fresh against the snapshot on every request — never
	// positively cached past it.
	switch {
	case !entry.Installed:
		writeCapabilityError(w, errenv.CodeModuleNotInstalled)
		return
	case !entry.Enabled:
		writeCapabilityError(w, errenv.CodeModuleDisabled)
		return
	case len(entry.MissingDependencies) > 0:
		writeCapabilityError(w, errenv.CodeModuleDependencyMissing)
		return
	}

	host := fmt.Sprintf("%s:%d", moduleHost(moduleKey), entry.Port)
	correlationID, _ := obs.CorrelationFromContext(r.Context())

	// Record this proxied request's outcome at the gateway's own boundary — start is
	// taken here (immediately before the actual upstream call), not at ServeHTTP's entry, so
	// catalog-lookup/capability-check time above never counts as "upstream latency". rec wraps w
	// so ModifyResponse (the success path) AND ErrorHandler (the unreachable-upstream path,
	// which writes its own response and never calls ModifyResponse) both observe the real status
	// this handler wrote, exactly once.
	upstreamStart := time.Now()
	rec := &httpx.StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
	// Deferred so a client abort mid-body (ReverseProxy panics http.ErrAbortHandler, which
	// httpx.Recover re-raises for net/http to swallow) still records the upstream outcome. A
	// body over limitBody's cap (413, writeProxyError) is the client's doing, not an upstream
	// outcome, so it is not recorded at all.
	tooLarge := false
	defer func() {
		if !tooLarge {
			p.Metrics.RecordGatewayUpstream(moduleKey, rec.Status, time.Since(upstreamStart))
		}
	}()

	proxy := &httputil.ReverseProxy{
		Transport: p.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// pr.Out starts as a full clone of pr.In (net/http/httputil): touching ONLY
			// Scheme/Host here leaves Path, RawPath, and RawQuery byte-for-byte identical
			// to the inbound request — true opaque forwarding, not a re-join of segments.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = host
			pr.Out.Host = pr.In.Host // preserve inbound Host header (matches the NewSingleHostReverseProxy default)
			if correlationID != "" {
				pr.Out.Header.Set("x-correlation-id", correlationID)
			}
			copyForwardedFor(pr)
			// Authorization is left untouched by construction (it's part of the cloned
			// header set) — forwarded verbatim.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			tooLarge = writeProxyError(w, err, "module unreachable")
		},
	}
	proxy.ServeHTTP(rec, r)
}

func writeCapabilityError(w http.ResponseWriter, code string) {
	errenv.WriteError(w, http.StatusForbidden, errenv.APIError{
		Code:    code,
		Message: "module capability check failed",
	})
}
