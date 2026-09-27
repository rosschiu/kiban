// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/registry"
)

// registryStub is a mutable in-memory stand-in for the registry's two public-read endpoints
// (GET /api/platform/catalog, GET /api/platform/capabilities) that the gateway's CatalogClient
// reads. Most proxy behavior (unknown key, the 3-code order, opaque forwarding, unreachable
// backends) is exercised against this stub — no live registry/Postgres needed for it, mirroring
// how the fake JWKS server stands in for Keycloak in token_test.go. The one exception is
// TestProxy_ZeroEditModuleRouting below, which deliberately uses the REAL registry package
// against the live dev Postgres, because the thing that test proves ("no gateway restart/config
// change") is only meaningful against the real registry service.
type registryStub struct {
	mu       sync.Mutex
	catalog  []catalogRow
	capsByID map[string][]string // module -> missingDependencies
	server   *httptest.Server
}

func newRegistryStub(t *testing.T) *registryStub {
	t.Helper()
	s := &registryStub{capsByID: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/platform/catalog", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		rows := append([]catalogRow(nil), s.catalog...)
		s.mu.Unlock()
		writeTestEnvelope(w, rows)
	})
	mux.HandleFunc("/api/platform/capabilities", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		rows := make([]capabilityRow, 0, len(s.catalog))
		for _, c := range s.catalog {
			rows = append(rows, capabilityRow{Module: c.ModuleKey, MissingDependencies: s.capsByID[c.ModuleKey]})
		}
		s.mu.Unlock()
		writeTestEnvelope(w, rows)
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func writeTestEnvelope(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
}

// set replaces the stub's entire catalog/capability state.
func (s *registryStub) set(rows []catalogRow, missing map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.catalog = rows
	if missing == nil {
		missing = map[string][]string{}
	}
	s.capsByID = missing
}

func mustParsePort(t *testing.T, rawURL string) int32 {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port from %q: %v", rawURL, err)
	}
	return int32(port)
}

// readyEntry is shorthand for a catalog row that's fully installed+enabled+dependency-complete,
// pointed at backend (an httptest.Server URL) via defaultModuleHost's port-only resolution
// (backend must be bound to 127.0.0.1, which httptest servers are by default).
func readyEntry(t *testing.T, moduleKey, backend string) catalogRow {
	return catalogRow{
		ModuleKey: moduleKey, BasePath: "/api/" + moduleKey, HealthPath: "/health",
		Port: mustParsePort(t, backend), Installed: true, Enabled: true,
	}
}

func newTestProxyServer(t *testing.T, registryBaseURL string) *httptest.Server {
	t.Helper()
	catalog := NewCatalogClient(registryBaseURL, nil)
	proxy := NewModuleProxy(catalog)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Emulates Routes()'s pattern match without needing the full mux (moduleKey = first
		// path segment after /api/, same extraction the real mux's {moduleKey} performs).
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/")
		key, _, _ := strings.Cut(trimmed, "/")
		r.SetPathValue("moduleKey", key)
		proxy.ServeHTTP(w, r)
	}))
}

func decodeErrorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return body.Error.Code
}

func TestProxy_UnknownModuleIs404(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set(nil, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/ghost/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "NOT_FOUND" {
		t.Errorf("code = %q, want NOT_FOUND", code)
	}
}

func TestProxy_CapabilityOrder_NotInstalledFirst(t *testing.T) {
	reg := newRegistryStub(t)
	// Deliberately not-installed AND not-enabled AND missing a dependency, to prove
	// MODULE_NOT_INSTALLED wins the order over the other two applicable codes.
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health", Port: 9999,
		Installed: false, Enabled: false,
	}}, map[string][]string{"foo": {"bar"}})
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "MODULE_NOT_INSTALLED" {
		t.Errorf("code = %q, want MODULE_NOT_INSTALLED", code)
	}
}

func TestProxy_CapabilityOrder_DisabledSecond(t *testing.T) {
	reg := newRegistryStub(t)
	// Installed but disabled AND missing a dependency: MODULE_DISABLED must win over
	// MODULE_DEPENDENCY_MISSING.
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health", Port: 9999,
		Installed: true, Enabled: false,
	}}, map[string][]string{"foo": {"bar"}})
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "MODULE_DISABLED" {
		t.Errorf("code = %q, want MODULE_DISABLED", code)
	}
}

func TestProxy_CapabilityOrder_DependencyMissingThird(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health", Port: 9999,
		Installed: true, Enabled: true,
	}}, map[string][]string{"foo": {"bar"}})
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "MODULE_DEPENDENCY_MISSING" {
		t.Errorf("code = %q, want MODULE_DEPENDENCY_MISSING", code)
	}
}

func TestProxy_Ready_ForwardsToBackend(t *testing.T) {
	backendHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "foo", backend.URL)}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !backendHit {
		t.Error("backend was never reached")
	}
}

// TestProxy_OpaqueForwarding_OddSegment proves the opaque forwarding requirement:
// the backend receives the ORIGINAL request-target byte-for-byte, including an encoded slash in
// an odd segment and the raw query string: "/api/m/v9/x%2Fy?q=1".
func TestProxy_OpaqueForwarding_OddSegment(t *testing.T) {
	var gotRequestURI, gotAuth, gotCorrelation string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		gotAuth = r.Header.Get("Authorization")
		gotCorrelation = r.Header.Get("x-correlation-id")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "m", backend.URL)}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/api/m/v9/x%2Fy?q=1", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer opaque-token-value")
	req.Header.Set("x-correlation-id", "corr-123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	const want = "/api/m/v9/x%2Fy?q=1"
	if gotRequestURI != want {
		t.Errorf("backend saw RequestURI = %q, want %q (opaque forwarding broke it)", gotRequestURI, want)
	}
	if gotAuth != "Bearer opaque-token-value" {
		t.Errorf("backend saw Authorization = %q, want it forwarded verbatim", gotAuth)
	}
	if gotCorrelation != "corr-123" {
		t.Errorf("backend saw x-correlation-id = %q, want corr-123 forwarded", gotCorrelation)
	}
}

// TestProxy_Unreachable503 proves Design's "Module unreachable => 503": the catalog resolves a
// fully-ready module whose port has nothing listening.
func TestProxy_Unreachable503(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health",
		Port:      1, // reserved/unlisted port — connection refused
		Installed: true, Enabled: true,
	}}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "MODULE_UNAVAILABLE" {
		t.Errorf("code = %q, want MODULE_UNAVAILABLE", code)
	}
}

// TestProxy_RegistryUnreachable503 proves the catalog-fetch failure path (no snapshot ever
// obtained) also fails closed with 503, rather than crashing or routing nowhere.
func TestProxy_RegistryUnreachable503(t *testing.T) {
	catalog := NewCatalogClient("http://127.0.0.1:1", nil) // nothing listens here
	proxy := NewModuleProxy(catalog)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("moduleKey", "foo")
		proxy.ServeHTTP(w, r)
	}))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestProxy_SlowUpstream_BoundedLatency_503 proves the upstream latency bound: a module upstream that
// accepts the TCP connection but never writes response headers must not hang the gateway request
// for anywhere close to the server's own 10s WriteTimeout (cmd/gateway/main.go:152) — the proxy's
// own KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT bounds it well before that backstop is ever reached,
// and the request still resolves to the same 503 MODULE_UNAVAILABLE TestProxy_Unreachable503
// proves for a connection-refused backend (errenv convention: an upstream that can't complete
// the request in time is indistinguishable from one that was never reachable at all).
func TestProxy_SlowUpstream_BoundedLatency_503(t *testing.T) {
	t.Setenv("KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT", "300ms")
	t.Setenv("KIBAN_MODULE_DIAL_TIMEOUT", "300ms")

	unblock := make(chan struct{})
	slowBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock // never writes headers until the test explicitly releases it (or exits)
	}))
	// t.Cleanup runs LIFO: registering Close() first and the unblock-close second means the
	// unblock close runs FIRST when the test ends, freeing the handler goroutine still parked on
	// <-unblock so slowBackend.Close() (which waits for all connections to finish) can actually
	// complete — the reverse order deadlocks forever, since Close() would block before the
	// cleanup that unblocks the handler ever gets a chance to run.
	t.Cleanup(slowBackend.Close)
	t.Cleanup(func() { close(unblock) })

	reg := newRegistryStub(t)
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health",
		Port:      mustParsePort(t, slowBackend.URL),
		Installed: true, Enabled: true,
	}}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	start := time.Now()
	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	// Bounded well under the server's 10s WriteTimeout — 3s gives ample margin over the 300ms
	// configured timeout while still proving this isn't racing (or relying on) that backstop.
	if elapsed >= 3*time.Second {
		t.Fatalf("request took %v, want well under the 10s server WriteTimeout (proxy transport timeout should have fired first)", elapsed)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "MODULE_UNAVAILABLE" {
		t.Errorf("code = %q, want MODULE_UNAVAILABLE", code)
	}
}

// TestProxy_FastUpstream_UnaffectedByTimeout proves the explicit transport timeout added in
// part (b) leaves ordinary, fast-responding upstreams completely unaffected — same behavior as
// before the timeout existed.
func TestProxy_FastUpstream_UnaffectedByTimeout(t *testing.T) {
	t.Setenv("KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT", "300ms")

	fastBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"fast"}`))
	}))
	defer fastBackend.Close()

	reg := newRegistryStub(t)
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health",
		Port:      mustParsePort(t, fastBackend.URL),
		Installed: true, Enabled: true,
	}}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/foo/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestProxy_ZeroEditModuleRouting is the fake-module-row proof. It
// runs the REAL registry package (internal/registry) against the live dev Postgres — the
// registry's own programmatic seeding path (Store.Seed) IS the registry's module-registration
// API today (no HTTP "create module" endpoint exists yet) — wrapped in a real HTTP server so the gateway
// talks to it exactly as it would talk to the production registry service. A single, already-
// running CatalogClient/gateway observes the new module with NO restart and NO gateway code or
// config change: only a new registry row (via the registry's own Seed call, standing in for
// "register a module") plus the passage of one cache TTL window.
func TestProxy_ZeroEditModuleRouting(t *testing.T) {
	admin := gatewayAdminPool(t)
	registryPool := gatewayRegistryPool(t)
	resetGatewayRegistryFixtures(t, admin)

	store := registry.NewStore(registryPool)
	auditWriter := gatewayTestAuditWriter(t)
	svc := registry.NewService(store, registry.NewDenyAllAuthorizer(), auditWriter)
	registrySrv := httptest.NewServer(svc.Routes())
	defer registrySrv.Close()

	// Backend the fake module will resolve to — started BEFORE the gateway ever sees the
	// module, to make the "gateway routes with zero edits" point unambiguous: nothing about
	// the gateway process changes between "module doesn't exist" and "module exists".
	moduleHit := false
	moduleBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		moduleHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"hello from the fake module"}`))
	}))
	defer moduleBackend.Close()

	// One gateway, wired once, never touched again for the rest of this test.
	catalog := NewCatalogClient(registrySrv.URL, nil)
	proxy := NewModuleProxy(catalog)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/")
		key, _, _ := strings.Cut(trimmed, "/")
		r.SetPathValue("moduleKey", key)
		proxy.ServeHTTP(w, r)
	}))
	defer gw.Close()

	// Before registration: unknown key -> 404.
	resp, err := http.Get(gw.URL + "/api/zzfake/ping")
	if err != nil {
		t.Fatalf("GET (before): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("before registration: status = %d, want 404", resp.StatusCode)
	}

	// "Register" the fake module — the registry's own Seed API, installed+enabled, pointed at
	// the already-running backend. Nothing about the gateway process is touched.
	manifest := []registry.ModuleManifest{{
		ModuleKey: "zzfake", DisplayName: "ZZ Fake", ScopeType: "company", Mandatory: false,
		BasePath: "/api/zzfake", HealthPath: "/health", Port: mustParsePort(t, moduleBackend.URL),
		LicenseClass: "foundation", ManifestVersion: "0.1.0",
	}}
	if err := store.Seed(context.Background(), manifest, map[string]bool{"zzfake": true}); err != nil {
		t.Fatalf("seed fake module: %v", err)
	}

	// The gateway's catalog cache TTL is 5s; poll until the SAME running gateway picks up the
	// new row on its own, with no restart and no code/config change.
	deadline := time.Now().Add(catalogCacheTTL + 3*time.Second)
	var last *http.Response
	for time.Now().Before(deadline) {
		r, err := http.Get(gw.URL + "/api/zzfake/ping")
		if err != nil {
			t.Fatalf("GET (polling): %v", err)
		}
		if r.StatusCode == http.StatusOK {
			last = r
			break
		}
		r.Body.Close()
		time.Sleep(200 * time.Millisecond)
	}
	if last == nil {
		t.Fatal("gateway never picked up the newly-registered module within the cache TTL window")
	}
	defer last.Body.Close()
	if !moduleHit {
		t.Error("the fake module's backend was never actually reached")
	}
}

// TestModuleHost_EnvOverride proves the KIBAN_MODULE_HOST_<MODULEKEY> escape hatch documented on
// moduleHost: set for a given module key, it wins over defaultModuleHost; unset, every module
// still resolves to 127.0.0.1.
func TestModuleHost_EnvOverride(t *testing.T) {
	const key = "zzoverride"
	envName := "KIBAN_MODULE_HOST_" + strings.ToUpper(key)

	if got := moduleHost(key); got != defaultModuleHost {
		t.Fatalf("moduleHost(%q) (no override) = %q, want %q", key, got, defaultModuleHost)
	}

	t.Setenv(envName, "10.0.0.9")
	if got := moduleHost(key); got != "10.0.0.9" {
		t.Errorf("moduleHost(%q) (override set) = %q, want 10.0.0.9", key, got)
	}

	// A different module key never sees another module's override.
	if got := moduleHost("some-other-module"); got != defaultModuleHost {
		t.Errorf("moduleHost(other) = %q, want %q (override must not leak across module keys)", got, defaultModuleHost)
	}
}

// TestProxy_CorrelationIDForwardedFromContext proves the correlationID != "" branch in
// ServeHTTP's Rewrite func: when obs.CorrelationFromContext finds a correlation ID on the
// inbound request's context (as httpx.Correlation's real middleware sets it in production —
// this test sets it directly to isolate ServeHTTP's own forwarding logic from that middleware),
// the backend receives it as x-correlation-id. Also proves the negative: no correlation ID in
// context => the header is never set at all (not even empty), covering both directions of the
// same conditional.
func TestProxy_CorrelationIDForwardedFromContext(t *testing.T) {
	var gotCorrelation string
	var sawHeader bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCorrelation, sawHeader = r.Header.Get("x-correlation-id"), r.Header.Get("x-correlation-id") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	reg := newRegistryStub(t)
	reg.set([]catalogRow{readyEntry(t, "m", backend.URL)}, nil)
	catalog := NewCatalogClient(reg.server.URL, nil)
	proxy := NewModuleProxy(catalog)

	// With a correlation ID on the context.
	req := httptest.NewRequest(http.MethodGet, "/api/m/ping", nil)
	req.SetPathValue("moduleKey", "m")
	req = req.WithContext(obs.ContextWithCorrelation(req.Context(), "ctx-corr-1"))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotCorrelation != "ctx-corr-1" {
		t.Errorf("backend saw x-correlation-id = %q, want ctx-corr-1", gotCorrelation)
	}

	// Without one — the header must never be set at all.
	req2 := httptest.NewRequest(http.MethodGet, "/api/m/ping", nil)
	req2.SetPathValue("moduleKey", "m")
	rec2 := httptest.NewRecorder()
	proxy.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}
	if sawHeader {
		t.Errorf("backend saw x-correlation-id = %q, want no header at all when context has none", gotCorrelation)
	}
}

// TestProxy_OneTransport_KeepAliveReuse: the ModuleProxy's single transport reuses
// upstream connections — 100 proxied requests dial the backend far fewer than 100 times.
func TestProxy_OneTransport_KeepAliveReuse(t *testing.T) {
	stub := newRegistryStub(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	stub.set([]catalogRow{readyEntry(t, "ka", backend.URL)}, nil)

	proxy := NewModuleProxy(NewCatalogClient(stub.server.URL, nil))
	var dials atomic.Int64
	inner := proxy.transport.DialContext
	proxy.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return inner(ctx, network, addr)
	}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("moduleKey", "ka")
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(gw.Close)

	for i := 0; i < 100; i++ {
		resp, err := http.Get(gw.URL + "/api/ka/ping")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	if n := dials.Load(); n > 5 {
		t.Fatalf("upstream dials = %d over 100 requests, want keep-alive reuse (<= 5)", n)
	}
}
