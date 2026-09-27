// SPDX-License-Identifier: Apache-2.0

// Route-level tests for the root-relative Keycloak mounts: the `/resources/`
// and `/realms/` mounts wired in routes.go, exercised through the FULL Routes() mux (not just
// the handler in isolation, unlike auth_proxy_test.go's NewKeycloakVerbatimProxy tests) — proves
// mux precedence doesn't let the SPA fallback (or any other route) shadow these prefixes, and
// that the SPA fallback itself is untouched for a genuine shell route.
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

// buildTestRoutesWithKeycloak is buildTestRoutes (static_test.go) with a caller-supplied
// Keycloak backend instead of the fixed always-200 stub, and a real static dir so the SPA
// fallback path can be told apart from a Keycloak-proxied one.
func buildTestRoutesWithKeycloak(t *testing.T, keycloak http.Handler, staticDir string) http.Handler {
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

	keycloakSrv := httptest.NewServer(keycloak)
	t.Cleanup(keycloakSrv.Close)

	adminClient := NewAuthzAdminClient(registrySrv.URL)

	return Routes(RoutesConfig{
		Verifier:        verifier,
		Catalog:         catalog,
		RegistryBaseURL: registrySrv.URL,
		KeycloakBaseURL: keycloakSrv.URL,
		AdminClient:     adminClient,
		StaticDir:       staticDir,
		AuthzBaseURL:    registrySrv.URL,
		OrgBaseURL:      registrySrv.URL,
		IdentityBaseURL: registrySrv.URL,
	})
}

// TestRoutes_ResourcesAsset_ReachesKeycloakByteForByte proves a `/resources/...` theme-asset
// request reaches Keycloak through the full mux (not the SPA fallback) with its Content-Type and
// body forwarded byte-for-byte.
func TestRoutes_ResourcesAsset_ReachesKeycloakByteForByte(t *testing.T) {
	assetBody := []byte("body{color:red}")
	keycloak := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resources/abc123/login/keycloak.v2/css/login.css" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write(assetBody)
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa-shell</html>"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	handler := buildTestRoutesWithKeycloak(t, keycloak, dir)

	req := httptest.NewRequest(http.MethodGet, "/resources/abc123/login/keycloak.v2/css/login.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/css" {
		t.Errorf("Content-Type = %q, want text/css", ct)
	}
	if rec.Body.String() != string(assetBody) {
		t.Errorf("body = %q, want byte-for-byte %q", rec.Body.String(), string(assetBody))
	}
}

// TestRoutes_RealmsPage_Reachable proves a `/realms/...` action page (Forgot-Password's shape)
// reaches Keycloak through the full mux.
func TestRoutes_RealmsPage_Reachable(t *testing.T) {
	keycloak := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/kiban/login-actions/reset-credentials" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>forgot-password-form</html>"))
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa-shell</html>"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	handler := buildTestRoutesWithKeycloak(t, keycloak, dir)

	req := httptest.NewRequest(http.MethodGet, "/realms/kiban/login-actions/reset-credentials?client_id=kiban-frontend", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "forgot-password-form") {
		t.Errorf("body = %q, want the Keycloak-rendered page, not the SPA shell", rec.Body.String())
	}
}

// TestRoutes_SPAFallback_UntouchedForShellRoute proves a genuine shell route (anything not under
// /api, /auth, /internal, /resources, /realms) still falls through to the SPA fallback — the new
// mounts must not shadow it.
func TestRoutes_SPAFallback_UntouchedForShellRoute(t *testing.T) {
	keycloak := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("keycloak should never be reached for a shell route, got %s", r.URL.Path)
		http.NotFound(w, r)
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa-shell</html>"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	handler := buildTestRoutesWithKeycloak(t, keycloak, dir)

	req := httptest.NewRequest(http.MethodGet, "/some-shell-route", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "spa-shell") {
		t.Errorf("body = %q, want the SPA shell's index.html", rec.Body.String())
	}
}
