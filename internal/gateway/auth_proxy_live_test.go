// SPDX-License-Identifier: Apache-2.0

//go:build live

// Live proof for the /auth reverse proxy: exercised against the REAL `make dev`
// Keycloak. Build-tag-fenced out of `make check`/`make test` — run explicitly with
// `go test -tags live ./internal/gateway/ -run TestLive -v` (same convention as
// token_live_test.go).
package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tlsRequest marks req as having arrived over TLS — in the real deployment shape every request
// this proxy sees genuinely did (the gateway only terminates TLS, on :8443; internal/gateway/
// auth_proxy.go's NewAuthProxy calls ProxyRequest.SetXForwarded, which reads req.TLS to decide
// X-Forwarded-Proto, and KC_PROXY_HEADERS=xforwarded (infra/compose.yaml) makes Keycloak trust
// that header for its own "sslRequired" enforcement). httptest.NewRequest builds a plain HTTP
// request with no TLS state by default; without this, Keycloak correctly (per its own
// sslRequired="external" policy) 403s these calls with "HTTPS required" — a test artifact of
// not simulating the real TLS-terminated shape, not a proxy bug.
func tlsRequest(req *http.Request) *http.Request {
	req.TLS = &tls.ConnectionState{}
	return req
}

// TestLive_AuthProxy_RoundTrip proves the gateway's /auth/* reverse proxy actually reaches the
// real dev Keycloak and returns its response unmodified in shape: GET /auth/realms/{realm}/
// protocol/openid-connect/certs through the gateway must come back exactly as Keycloak's own
// JWKS document (the same one TestLive_TokenVerifier_RealKeycloak already fetches directly).
func TestLive_AuthProxy_RoundTrip(t *testing.T) {
	baseURL := "http://127.0.0.1:" + gatewayTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := gatewayTestEnv(t, "KEYCLOAK_REALM")

	target := mustParseAbsoluteURL(baseURL)
	proxy := NewAuthProxy(target, false, nil)

	req := tlsRequest(httptest.NewRequest(http.MethodGet, "/auth/realms/"+realm+"/protocol/openid-connect/certs", nil))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var proxied struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &proxied); err != nil {
		t.Fatalf("proxied body not valid JWKS JSON: %v (%s)", err, rec.Body.String())
	}
	if len(proxied.Keys) == 0 {
		t.Error("expected at least one key in the proxied JWKS response")
	}

	// Fetch the same document directly from Keycloak and compare, proving the proxy forwarded
	// it byte-for-byte (modulo header hygiene, which is exercised separately).
	direct, err := http.Get(baseURL + "/realms/" + realm + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("direct fetch: %v", err)
	}
	defer direct.Body.Close()
	var directBody struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(direct.Body).Decode(&directBody); err != nil {
		t.Fatalf("decode direct body: %v", err)
	}
	if len(directBody.Keys) != len(proxied.Keys) {
		t.Errorf("proxied key count = %d, direct key count = %d, want equal", len(proxied.Keys), len(directBody.Keys))
	}
}

// TestLive_AuthProxy_NoAuthRequired proves /auth/* needs no bearer token at all — this same
// request would 401 on /api/*.
func TestLive_AuthProxy_NoAuthRequired(t *testing.T) {
	baseURL := "http://127.0.0.1:" + gatewayTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := gatewayTestEnv(t, "KEYCLOAK_REALM")

	target := mustParseAbsoluteURL(baseURL)
	proxy := NewAuthProxy(target, false, nil)

	req := tlsRequest(httptest.NewRequest(http.MethodGet, "/auth/realms/"+realm+"/.well-known/openid-configuration", nil))
	// Deliberately no Authorization header.
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no Authorization header (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "issuer") {
		t.Errorf("expected an OIDC discovery document, got %s", rec.Body.String())
	}
}

// pkceVerifierAndChallenge builds a throwaway PKCE pair — kiban-frontend (internal/bootstrap/
// realm.go) requires S256 PKCE on every authorization request, even one this test never carries
// through to a token exchange.
func pkceVerifierAndChallenge(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// TestLive_KeycloakVerbatimProxy_CookieJar is the cookie-jar proof for the question of whether
// Set-Cookie Path rewriting must be suppressed on the un-prefixed `/resources/`/`/realms/`
// routes. It mounts
// BOTH the existing `/auth/*` proxy (NewAuthProxy — Path rewritten) and the new verbatim
// `/realms/*` proxy (NewKeycloakVerbatimProxy — Path untouched) side by side over the SAME live
// Keycloak, and drives the identical OIDC authorize endpoint
// (`/realms/{realm}/protocol/openid-connect/auth` — itself a "/realms/" path, so it's reachable
// through either mount) through each — Keycloak sets a session-restart cookie on that endpoint
// either way, giving a real cookie from the real Keycloak to test path-scoping against with a
// genuine net/http/cookiejar.Jar (the same RFC 6265 §5.1.4 path-match logic a browser applies).
//
// Verdict this test proves: Set-Cookie Path rewriting MUST be suppressed on the un-prefixed
// routes. A cookie
// picked up through `/auth/realms/...` (Path=/auth/realms/.../) is never offered by the jar to a
// plain `/realms/...` URL, and the reverse — a cookie picked up through the verbatim
// `/realms/...` mount keeps its own un-prefixed Path and IS still offered to a follow-up plain
// `/realms/...` URL (so a same-mount, multi-step flow like Forgot-Password stays session-
// continuous) but is NOT offered to an `/auth/realms/...` URL. Rewriting `/auth` onto the
// verbatim mount's cookies (i.e. reusing NewAuthProxy unmodified for these routes) would have
// broken that same-mount continuity — the exact "Restart login cookie not found" bug class
// NewAuthProxy's rewriteSetCookiePaths fixes for the mirror-image case.
func TestLive_KeycloakVerbatimProxy_CookieJar(t *testing.T) {
	baseURL := "http://127.0.0.1:" + gatewayTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := gatewayTestEnv(t, "KEYCLOAK_REALM")
	target := mustParseAbsoluteURL(baseURL)

	mux := http.NewServeMux()
	mux.Handle("/auth/", NewAuthProxy(target, false, nil))
	mux.Handle("/realms/", NewKeycloakVerbatimProxy(target, false, nil))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	authQuery := func(t *testing.T) string {
		_, challenge := pkceVerifierAndChallenge(t)
		return url.Values{
			"client_id":             {"kiban-frontend"},
			"redirect_uri":          {"http://localhost:5173/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"state":                 {"cookie-jar-test"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}.Encode()
	}

	// Step 1: the authorize endpoint through the /auth-prefixed mount. Its Set-Cookie Path must
	// gain the /auth prefix (NewAuthProxy's existing, unchanged behavior).
	jar1, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client1 := &http.Client{Jar: jar1}
	resp1, err := client1.Get(srv.URL + "/auth/realms/" + realm + "/protocol/openid-connect/auth?" + authQuery(t))
	if err != nil {
		t.Fatalf("GET via /auth: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("GET via /auth status = %d, want 200", resp1.StatusCode)
	}
	var sawAuthCookie bool
	for _, c := range resp1.Cookies() {
		sawAuthCookie = true
		if !strings.HasPrefix(c.Path, "/auth/") {
			t.Errorf("cookie %s set via the /auth mount has Path=%q, want it prefixed with /auth/", c.Name, c.Path)
		}
	}
	if !sawAuthCookie {
		t.Fatal("expected at least one Set-Cookie from the /auth-mounted authorize endpoint")
	}

	// Step 2: the SAME authorize request through the verbatim /realms mount, a fresh jar so the
	// two flows' cookies never mix before the cross-mount assertions below.
	jar2, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client2 := &http.Client{Jar: jar2}
	resp2, err := client2.Get(srv.URL + "/realms/" + realm + "/protocol/openid-connect/auth?" + authQuery(t))
	if err != nil {
		t.Fatalf("GET via /realms: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET via /realms status = %d, want 200", resp2.StatusCode)
	}
	var sawRealmsCookie bool
	for _, c := range resp2.Cookies() {
		sawRealmsCookie = true
		if strings.HasPrefix(c.Path, "/auth") {
			t.Errorf("cookie %s set via the verbatim /realms mount has Path=%q, want it UNTOUCHED (no /auth prefix)", c.Name, c.Path)
		}
	}
	if !sawRealmsCookie {
		t.Fatal("expected at least one Set-Cookie from the verbatim-mounted authorize endpoint")
	}

	// Step 3: the cross-mount proof, using the jar's OWN RFC 6265 path-match logic (the same
	// logic a browser applies) instead of re-deriving it by hand.
	plainRealmsURL, err := url.Parse(srv.URL + "/realms/" + realm + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("parse plain realms URL: %v", err)
	}
	if got := jar1.Cookies(plainRealmsURL); len(got) != 0 {
		t.Errorf("jar seeded via /auth offers %d cookie(s) to a plain /realms/ URL, want 0 — Path scoping would leak the /auth session across mounts", len(got))
	}

	// The mirror: the jar seeded via the verbatim mount MUST still offer its cookie back to a
	// follow-up plain /realms/ URL (same-mount flow continuity, e.g. Forgot-Password's
	// multi-step form)...
	if got := jar2.Cookies(plainRealmsURL); len(got) == 0 {
		t.Error("jar seeded via the verbatim /realms mount offers 0 cookies to a follow-up plain /realms/ URL, want the session cookie to still match — Path scoping would break same-mount flow continuity")
	}
	// ...but must NOT offer that same cookie to the /auth-prefixed URL (the reverse leak
	// direction).
	authRealmsURL, err := url.Parse(srv.URL + "/auth/realms/" + realm + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("parse /auth realms URL: %v", err)
	}
	if got := jar2.Cookies(authRealmsURL); len(got) != 0 {
		t.Errorf("jar seeded via the verbatim /realms mount offers %d cookie(s) to an /auth-prefixed URL, want 0", len(got))
	}
}
