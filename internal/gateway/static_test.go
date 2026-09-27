// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestStatic_ServesRealFile proves a request that resolves to a real file on disk is served
// as-is, not the SPA fallback.
func TestStatic_ServesRealFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>index</html>")
	writeTestFile(t, dir, "app.js", "console.log('app')")

	handler := NewStaticHandler(dir)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "console.log('app')" {
		t.Errorf("body = %q, want the real file content", rec.Body.String())
	}
}

// TestStatic_SPAFallback_ServesIndexForUnknownPath proves an unresolvable path (a client-side
// SPA route) falls back to index.html rather than 404ing.
func TestStatic_SPAFallback_ServesIndexForUnknownPath(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>spa-shell</html>")

	handler := NewStaticHandler(dir)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/companies/42/settings", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "spa-shell") {
		t.Errorf("body = %q, want index.html content", rec.Body.String())
	}
}

// TestStatic_CacheControl proves the caching split a stale bundle must never survive:
// content-hashed files under /assets/ cache forever (immutable), while index.html —
// served directly, at "/", or as the SPA fallback — and any non-assets file must revalidate
// (no-cache), so a redeploy is picked up on the next ordinary page load instead of browsers
// heuristically caching a pre-redeploy bundle off last-modified.
func TestStatic_CacheControl(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>index</html>")
	writeTestFile(t, dir, "assets/index-Do9P7ng-.js", "console.log('hashed')")
	writeTestFile(t, dir, "modules/notification/bundle.js", "console.log('module')")

	handler := NewStaticHandler(dir)
	cases := []struct {
		path       string
		want       string
		wantStatus int
	}{
		{"/assets/index-Do9P7ng-.js", "public, max-age=31536000, immutable", http.StatusOK},
		{"/", "no-cache", http.StatusOK},
		// http.FileServer canonicalizes /index.html to / with a 301 — the redirect itself must
		// carry no-cache too, so nothing about the entrypoint is ever heuristically cached.
		{"/index.html", "no-cache", http.StatusMovedPermanently},
		{"/companies/42/settings", "no-cache", http.StatusOK}, // SPA fallback
		{"/modules/notification/bundle.js", "no-cache", http.StatusOK},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.wantStatus {
			t.Fatalf("%s: status = %d, want %d", tc.path, rec.Code, tc.wantStatus)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.want {
			t.Errorf("%s: Cache-Control = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestStatic_ModuleBundlePath_ServedLikeAnyOtherFile proves module UI bundles under
// /modules/<key>/... need no gateway code beyond ordinary static serving.
func TestStatic_ModuleBundlePath_ServedLikeAnyOtherFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>shell</html>")
	writeTestFile(t, dir, "modules/timesheet/index.js", "export default {}")

	handler := NewStaticHandler(dir)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/modules/timesheet/index.js", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "export default {}" {
		t.Errorf("body = %q, want the module bundle file content", rec.Body.String())
	}
}

// TestStatic_NoDirectoryListing proves a bare directory (no index.html of its own) never lists
// its contents — it falls to the SPA fallback like any other unresolved path.
func TestStatic_NoDirectoryListing(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>shell</html>")
	writeTestFile(t, dir, "modules/timesheet/index.js", "export default {}")

	handler := NewStaticHandler(dir)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/modules/timesheet/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "index.js") || strings.Contains(strings.ToLower(rec.Body.String()), "index of") {
		t.Errorf("expected the SPA fallback body, got what looks like a directory listing: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "shell") {
		t.Errorf("expected the SPA fallback (index.html) body, got %q", rec.Body.String())
	}
}

// TestStatic_NoStaticDirConfigured_404sInsteadOfPanicking proves the "no KIBAN_STATIC_DIR set"
// case (no frontend bundle built yet) degrades to a clean 404, not a startup crash.
func TestStatic_NoStaticDirConfigured_404sInsteadOfPanicking(t *testing.T) {
	rec := httptest.NewRecorder()
	writeInternalNotFound(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// buildTestRoutes assembles a full Routes() handler backed entirely by fakes/httptest servers —
// used by the internal-path 404 test below, which needs to prove the behavior at the full
// mux-routing level (not just call one handler function directly).
func buildTestRoutes(t *testing.T) http.Handler {
	t.Helper()

	jwks := newFakeJWKSServer(t)
	verifier, err := NewTokenVerifier(context.Background(), jwks.URL+"/certs", testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(registrySrv.Close)
	catalog := NewCatalogClient(registrySrv.URL, nil)

	keycloakSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(keycloakSrv.Close)

	adminClient := NewAuthzAdminClient(registrySrv.URL)

	return Routes(RoutesConfig{
		Verifier:        verifier,
		Catalog:         catalog,
		RegistryBaseURL: registrySrv.URL,
		KeycloakBaseURL: keycloakSrv.URL,
		AdminClient:     adminClient,
		StaticDir:       "",
		AuthzBaseURL:    registrySrv.URL,
		OrgBaseURL:      registrySrv.URL,
		IdentityBaseURL: registrySrv.URL,
	})
}

// TestStatic_InternalPathAlwaysNotFound proves `/internal/*` is unreachable from outside the
// edge (404 always), unauthenticated or not, and
// regardless of what (if anything) a real internal service would have served at that path.
func TestStatic_InternalPathAlwaysNotFound(t *testing.T) {
	handler := buildTestRoutes(t)

	for _, path := range []string{
		"/internal/authz/effective-access/can",
		"/internal/platform/modules/foo/enable",
		"/internal/anything/at/all",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}

// TestStatic_RootServesSPAFallback proves "/" itself (no static dir configured, the default in
// this test harness) 404s cleanly rather than being swallowed by any other route.
func TestStatic_RootServesSPAFallback(t *testing.T) {
	handler := buildTestRoutes(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no KIBAN_STATIC_DIR configured in this test)", rec.Code)
	}
}

// TestStatic_CSPOnShellHTMLOnly proves the enforced Content-Security-Policy rides on the
// shell's HTML — index.html requested directly and every SPA-fallback render — and not on the
// hashed assets (a CSP on a script response is meaningless; the document's policy governs).
func TestStatic_CSPOnShellHTMLOnly(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", "<html>spa</html>")
	writeTestFile(t, dir, "assets/app.js", "console.log('app')")
	handler := NewStaticHandler(dir)

	for _, path := range []string{"/", "/index.html", "/app/some/route"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Content-Security-Policy"); got != shellCSP {
			t.Errorf("%s: Content-Security-Policy = %q, want the shell CSP", path, got)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("/assets/app.js: Content-Security-Policy = %q, want none", got)
	}
	if !strings.Contains(shellCSP, "default-src 'self'") || strings.Contains(shellCSP, "report-only") {
		t.Fatalf("shellCSP = %q, want an enforced default-src 'self' policy", shellCSP)
	}
}
