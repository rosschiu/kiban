// SPDX-License-Identifier: Apache-2.0

// Non-live unit tests for the /auth reverse proxy (internal/gateway/auth_proxy.go):
// the Host/X-Forwarded-* handling, the response-rewriting helpers (rewriteAuthOrigin,
// rewriteSetCookiePaths/prefixCookiePath), and NewAuthProxy's full Rewrite+ModifyResponse
// pipeline against a fake backend standing in for Keycloak — no live stack needed, so these run
// under `make check`/`go test ./...` like every other package's own unit suite.
package gateway

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// erroringReader always fails — used to force rewriteAuthOrigin's io.ReadAll error branch,
// which a well-formed response body never exercises.
type erroringReader struct{ err error }

func (r *erroringReader) Read([]byte) (int, error) { return 0, r.err }

func TestPrefixCookiePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"root path", "SESSION=abc; Path=/; HttpOnly", "SESSION=abc; Path=/auth/; HttpOnly"},
		{"sub path", "KC_RESTART=xyz; Path=/realms/kiban/; Secure", "KC_RESTART=xyz; Path=/auth/realms/kiban/; Secure"},
		{"already prefixed (idempotent)", "SESSION=abc; Path=/auth/realms/kiban/", "SESSION=abc; Path=/auth/realms/kiban/"},
		{"no path attribute at all", "FOO=bar", "FOO=bar; Path=/auth/"},
		{"path is the last attribute, no trailing segment", "A=1; Secure; Path=/x", "A=1; Secure; Path=/auth/x"},
		{"lowercase path attribute name", "A=1; path=/x", "A=1; Path=/auth/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := prefixCookiePath(c.in); got != c.want {
				t.Errorf("prefixCookiePath(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRewriteSetCookiePaths(t *testing.T) {
	t.Run("rewrites every Set-Cookie header present", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Add("Set-Cookie", "A=1; Path=/")
		resp.Header.Add("Set-Cookie", "B=2; Path=/realms/kiban/")
		rewriteSetCookiePaths(resp)

		got := resp.Header["Set-Cookie"]
		want := []string{"A=1; Path=/auth/", "B=2; Path=/auth/realms/kiban/"}
		if len(got) != len(want) {
			t.Fatalf("got %d Set-Cookie headers, want %d: %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("no Set-Cookie headers is a no-op", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		rewriteSetCookiePaths(resp)
		if _, ok := resp.Header["Set-Cookie"]; ok {
			t.Errorf("expected no Set-Cookie header to appear, got %v", resp.Header["Set-Cookie"])
		}
	})
}

func TestRewriteAuthOrigin(t *testing.T) {
	makeReq := func(proto, host string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth/x", nil)
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		if host != "" {
			req.Header.Set("X-Forwarded-Host", host)
		}
		return req
	}

	t.Run("rewrites origin URLs in a textual body", func(t *testing.T) {
		body := `<a href="https://127.0.0.1:8443/realms/kiban">x</a>`
		resp := &http.Response{
			Request: makeReq("https", "127.0.0.1:8443"),
			Header:  http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body:    io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteAuthOrigin(resp); err != nil {
			t.Fatalf("rewriteAuthOrigin: %v", err)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read rewritten body: %v", err)
		}
		want := `<a href="https://127.0.0.1:8443/auth/realms/kiban">x</a>`
		if string(got) != want {
			t.Errorf("body = %q, want %q", got, want)
		}
		if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(want)) {
			t.Errorf("Content-Length = %q, want %d", cl, len(want))
		}
	})

	t.Run("application/json bodies are also rewritten", func(t *testing.T) {
		body := `{"authorization_endpoint":"https://kiban.example/realms/kiban/protocol/openid-connect/auth"}`
		resp := &http.Response{
			Request: makeReq("https", "kiban.example"),
			Header:  http.Header{"Content-Type": {"application/json"}},
			Body:    io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteAuthOrigin(resp); err != nil {
			t.Fatalf("rewriteAuthOrigin: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(got), "https://kiban.example/auth/realms/kiban") {
			t.Errorf("body = %q, want it to contain the /auth-prefixed origin", got)
		}
	})

	t.Run("binary content types are left untouched", func(t *testing.T) {
		body := "binarydata"
		resp := &http.Response{
			Request: makeReq("https", "127.0.0.1:8443"),
			Header:  http.Header{"Content-Type": {"image/png"}},
			Body:    io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteAuthOrigin(resp); err != nil {
			t.Fatalf("rewriteAuthOrigin: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			t.Errorf("body = %q, want untouched %q", got, body)
		}
	})

	t.Run("propagates a body-read error", func(t *testing.T) {
		resp := &http.Response{
			Request: makeReq("https", "127.0.0.1:8443"),
			Header:  http.Header{"Content-Type": {"text/html"}},
			Body:    io.NopCloser(&erroringReader{err: io.ErrUnexpectedEOF}),
		}
		if err := rewriteAuthOrigin(resp); err == nil {
			t.Fatal("expected rewriteAuthOrigin to propagate the body-read error, got nil")
		}
	})

	t.Run("missing X-Forwarded headers is a no-op passthrough", func(t *testing.T) {
		body := `<a href="https://127.0.0.1:8443/realms/kiban">x</a>`
		resp := &http.Response{
			Request: makeReq("", ""),
			Header:  http.Header{"Content-Type": {"text/html"}},
			Body:    io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteAuthOrigin(resp); err != nil {
			t.Fatalf("rewriteAuthOrigin: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			t.Errorf("body = %q, want untouched %q (no X-Forwarded-* headers to rewrite against)", got, body)
		}
	})
}

// TestNewAuthProxy_RewritesOriginAndCookiePath is the end-to-end proof for the origin/cookie-path
// rewrite (auth_proxy.go's own comment): a fake backend standing in for
// Keycloak echoes back the X-Forwarded-Proto/-Host it received (exactly what Keycloak's own
// non-strict hostname resolution does once KC_PROXY_HEADERS=xforwarded trusts them) into a
// self-referencing form action, and sets a session cookie scoped to its own (un-/auth-prefixed)
// view of the request path — proving both rewrites land together through the real
// Rewrite+ModifyResponse pipeline, not just their standalone helper functions.
func TestNewAuthProxy_RewritesOriginAndCookiePath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/kiban/login" {
			http.NotFound(w, r)
			return
		}
		origin := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host")
		http.SetCookie(w, &http.Cookie{Name: "KC_RESTART", Value: "abc", Path: "/realms/kiban/", HttpOnly: true})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<form id="kc-form-login" action="%s/realms/kiban/login-actions/authenticate">`, origin)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewAuthProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/login", nil)
	req.Host = "gateway.example"
	req.TLS = &tls.ConnectionState{} // simulate the TLS-terminated request the real gateway always sees
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	wantAction := `action="https://gateway.example/auth/realms/kiban/login-actions/authenticate"`
	if !strings.Contains(body, wantAction) {
		t.Errorf("body = %s, want it to contain %q", body, wantAction)
	}

	var sawRestart bool
	for _, c := range rec.Result().Cookies() {
		if c.Name != "KC_RESTART" {
			continue
		}
		sawRestart = true
		if c.Path != "/auth/realms/kiban/" {
			t.Errorf("KC_RESTART cookie Path = %q, want /auth/realms/kiban/", c.Path)
		}
	}
	if !sawRestart {
		t.Fatal("KC_RESTART cookie not present in the proxied response")
	}
}

// TestNewAuthProxy_PathStripping proves the `/auth` prefix is stripped before reaching the
// backend, and that the root `/auth` path maps to `/` (both edge cases in the Rewrite func's own
// TrimPrefix logic).
func TestNewAuthProxy_PathStripping(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewAuthProxy(target, false, nil)

	cases := []struct {
		reqPath  string
		wantPath string
	}{
		{"/auth/realms/kiban/protocol/openid-connect/certs", "/realms/kiban/protocol/openid-connect/certs"},
		{"/auth", "/"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.reqPath, nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if gotPath != c.wantPath {
			t.Errorf("request %q reached backend as %q, want %q", c.reqPath, gotPath, c.wantPath)
		}
	}
}

// TestNewAuthProxy_BackendUnreachable proves the ErrorHandler's envelope ("keycloak
// unreachable" via errenv, 503) when the target can't be dialed at all.
func TestNewAuthProxy_BackendUnreachable(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:1") // reserved, nothing ever listens here
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	proxy := NewAuthProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "keycloak unreachable") {
		t.Errorf("body = %s, want it to mention \"keycloak unreachable\"", rec.Body.String())
	}
}

// TestNewAuthProxy_TrustedProxyForwardedHeaders is the regression proof for the public-mode
// login break: with TLS terminated one hop EARLIER at a shared
// edge (Traefik), the gateway itself is reached over plain HTTP, so SetXForwarded derives
// X-Forwarded-Proto=http — clobbering the edge's own correct `https` before Keycloak (or
// rewriteAuthOrigin, which matches on that same origin) ever sees it. The rendered login form's
// action then goes out un-rewritten (`https://…/realms/…`, no /auth) and the browser's POST
// 404s at the gateway. With trustForwardedHeaders=true the proxy must pass the EDGE's
// X-Forwarded-Proto/-Host through instead, restoring both Keycloak's view of the scheme and the
// body rewrite; with false (the default everywhere but explicit trusted-edge deployments) the
// old self-derived behavior must be untouched.
func TestNewAuthProxy_TrustedProxyForwardedHeaders(t *testing.T) {
	var gotProto, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotHost = r.Header.Get("X-Forwarded-Host")
		// Render what a KC_HOSTNAME-pinned Keycloak renders: an absolute form action at the
		// public https origin, no /auth prefix.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<form action="https://kiban.example/realms/kiban/login-actions/authenticate">`)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	newReq := func() *http.Request {
		// The public-mode shape: the request reached the gateway over PLAIN HTTP (no req.TLS),
		// carrying the TLS-terminating edge's own forwarded headers.
		req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/login", nil)
		req.Host = "kiban.example"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "kiban.example")
		return req
	}

	t.Run("trusted", func(t *testing.T) {
		proxy := NewAuthProxy(target, true, nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, newReq())

		if gotProto != "https" {
			t.Errorf("backend saw X-Forwarded-Proto = %q, want the edge's own \"https\"", gotProto)
		}
		if gotHost != "kiban.example" {
			t.Errorf("backend saw X-Forwarded-Host = %q, want kiban.example", gotHost)
		}
		wantAction := `action="https://kiban.example/auth/realms/kiban/login-actions/authenticate"`
		if !strings.Contains(rec.Body.String(), wantAction) {
			t.Errorf("body = %s, want it to contain %q", rec.Body.String(), wantAction)
		}
	})

	t.Run("untrusted keeps self-derived proto", func(t *testing.T) {
		proxy := NewAuthProxy(target, false, nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, newReq())

		if gotProto != "http" {
			t.Errorf("backend saw X-Forwarded-Proto = %q, want the self-derived \"http\" when untrusted", gotProto)
		}
	})
}

// TestRewriteRootRelativeRealmsLinks unit-tests the fix for the residual
// cookie-continuity gap TestLive_KeycloakVerbatimProxy_CookieJar (auth_proxy_live_test.go)
// surfaced: a root-relative `href="/realms/..."` (no origin, so rewriteAuthOrigin never touches
// it) must gain the `/auth` prefix so it stays on the same, cookie-compatible mount.
func TestRewriteRootRelativeRealmsLinks(t *testing.T) {
	t.Run("rewrites a root-relative href", func(t *testing.T) {
		body := `<a href="/realms/kiban/login-actions/reset-credentials?client_id=x">Forgot Password?</a>`
		resp := &http.Response{
			Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteRootRelativeRealmsLinks(resp); err != nil {
			t.Fatalf("rewriteRootRelativeRealmsLinks: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		want := `<a href="/auth/realms/kiban/login-actions/reset-credentials?client_id=x">Forgot Password?</a>`
		if string(got) != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})

	t.Run("already-prefixed links are left alone (idempotent)", func(t *testing.T) {
		body := `<a href="/auth/realms/kiban/login-actions/reset-credentials">x</a>`
		resp := &http.Response{
			Header: http.Header{"Content-Type": {"text/html"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteRootRelativeRealmsLinks(resp); err != nil {
			t.Fatalf("rewriteRootRelativeRealmsLinks: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			t.Errorf("body = %q, want untouched %q", got, body)
		}
	})

	t.Run("root-relative /resources references are left untouched", func(t *testing.T) {
		body := `<link href="/resources/abc/login/keycloak.v2/css/login.css">`
		resp := &http.Response{
			Header: http.Header{"Content-Type": {"text/html"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteRootRelativeRealmsLinks(resp); err != nil {
			t.Fatalf("rewriteRootRelativeRealmsLinks: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			t.Errorf("body = %q, want untouched %q (resources assets are stateless, no rewrite needed)", got, body)
		}
	})

	t.Run("binary content types are left untouched", func(t *testing.T) {
		body := "binarydata"
		resp := &http.Response{
			Header: http.Header{"Content-Type": {"image/png"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if err := rewriteRootRelativeRealmsLinks(resp); err != nil {
			t.Fatalf("rewriteRootRelativeRealmsLinks: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != body {
			t.Errorf("body = %q, want untouched %q", got, body)
		}
	})
}

// TestNewAuthProxy_RewritesRootRelativeRealmsLinks is the end-to-end proof through the real
// /auth proxy pipeline: a login page with BOTH an absolute self-referencing form action
// (rewriteAuthOrigin's job) and a root-relative Forgot-Password href
// (rewriteRootRelativeRealmsLinks's job) must get both rewritten together.
func TestNewAuthProxy_RewritesRootRelativeRealmsLinks(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<a href="/realms/kiban/login-actions/reset-credentials?client_id=x&tab_id=y">Forgot Password?</a>`)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewAuthProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/login", nil)
	req.Host = "gateway.example"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	want := `href="/auth/realms/kiban/login-actions/reset-credentials?client_id=x&tab_id=y"`
	if !strings.Contains(rec.Body.String(), want) {
		t.Errorf("body = %s, want it to contain %q", rec.Body.String(), want)
	}
}

// TestNewKeycloakVerbatimProxy_DoesNotRewriteRootRelativeRealmsLinks proves the verbatim mount
// (unlike NewAuthProxy) never runs rewriteRootRelativeRealmsLinks — a page reached bare via
// `/realms/` must not gain onward links back into the `/auth`-scoped cookie space its own
// (un-rewritten) cookie doesn't cover.
func TestNewKeycloakVerbatimProxy_DoesNotRewriteRootRelativeRealmsLinks(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<a href="/realms/kiban/login-actions/authenticate">continue</a>`)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewKeycloakVerbatimProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/realms/kiban/login-actions/reset-credentials", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	want := `href="/realms/kiban/login-actions/authenticate"`
	if !strings.Contains(rec.Body.String(), want) {
		t.Errorf("body = %s, want the root-relative href left UNTOUCHED (no /auth prefix): %q", rec.Body.String(), want)
	}
}

// TestNewKeycloakVerbatimProxy_PathPassthrough proves the verbatim variant forwards the
// inbound path UNCHANGED (no `/auth` strip, unlike NewAuthProxy's TestNewAuthProxy_PathStripping
// twin above) — the whole point of mounting it at `/resources/` and `/realms/` directly.
func TestNewKeycloakVerbatimProxy_PathPassthrough(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewKeycloakVerbatimProxy(target, false, nil)

	cases := []string{
		"/resources/abc123/login/keycloak.v2/css/login.css",
		"/realms/kiban/login-actions/reset-credentials",
	}
	for _, reqPath := range cases {
		req := httptest.NewRequest(http.MethodGet, reqPath, nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if gotPath != reqPath {
			t.Errorf("request %q reached backend as %q, want it unchanged", reqPath, gotPath)
		}
	}
}

// TestNewKeycloakVerbatimProxy_CookiePathNotRewritten is the cookie-jar proof: a session
// cookie Keycloak scopes to `Path=/realms/kiban/` while served through this un-prefixed route
// must keep that EXACT Path — not gain a `/auth` prefix the way NewAuthProxy's
// TestNewAuthProxy_RewritesOriginAndCookiePath proves for the `/auth`-prefixed route. The
// request that reaches this handler is genuinely on `/realms/kiban/...`, never
// `/auth/realms/kiban/...`; prefixing the cookie's Path would scope it to a path the browser is
// never actually on for this flow, so RFC 6265 §5.1.4's path-match rule would silently drop it
// from every follow-up request — reproducing, mirrored, the exact "Restart login cookie not
// found" bug class rewriteSetCookiePaths exists to prevent on the `/auth` side.
func TestNewKeycloakVerbatimProxy_CookiePathNotRewritten(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "KC_RESTART", Value: "xyz", Path: "/realms/kiban/", HttpOnly: true})
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewKeycloakVerbatimProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/realms/kiban/login-actions/reset-credentials", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	var sawRestart bool
	for _, c := range rec.Result().Cookies() {
		if c.Name != "KC_RESTART" {
			continue
		}
		sawRestart = true
		if c.Path != "/realms/kiban/" {
			t.Errorf("KC_RESTART cookie Path = %q, want the un-rewritten /realms/kiban/", c.Path)
		}
	}
	if !sawRestart {
		t.Fatal("KC_RESTART cookie not present in the proxied response")
	}
}

// TestNewKeycloakVerbatimProxy_OriginStillSpliced proves the verbatim variant still runs
// rewriteAuthOrigin/rewriteLocationHeader (the same origin/auth splice, ONLY for absolute
// URLs) — only the cookie-Path rewrite is suppressed, not the whole ModifyResponse pipeline.
func TestNewKeycloakVerbatimProxy_OriginStillSpliced(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<a href="https://gateway.example/realms/kiban/account">Account</a>`)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewKeycloakVerbatimProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/realms/kiban/login-actions/reset-credentials", nil)
	req.Host = "gateway.example"
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	want := `href="https://gateway.example/auth/realms/kiban/account"`
	if !strings.Contains(rec.Body.String(), want) {
		t.Errorf("body = %s, want it to contain %q", rec.Body.String(), want)
	}
}

// TestNewKeycloakVerbatimProxy_BinaryAssetPassthroughByteForByte proves theme assets under
// `/resources/*` (CSS/JS/images — binary-safe, no body rewrite needed) are forwarded
// byte-for-byte with their original Content-Type, since rewriteAuthOrigin already skips any
// non-textual content type (textualContentTypes).
func TestNewKeycloakVerbatimProxy_BinaryAssetPassthroughByteForByte(t *testing.T) {
	assetBody := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(assetBody)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewKeycloakVerbatimProxy(target, false, nil)

	req := httptest.NewRequest(http.MethodGet, "/resources/abc123/login/keycloak.v2/img/logo.png", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if !bytes.Equal(rec.Body.Bytes(), assetBody) {
		t.Errorf("body = %v, want byte-for-byte %v", rec.Body.Bytes(), assetBody)
	}
}

// TestNewAuthProxy_RewritesLocationHeader: Keycloak answers several browser-flow steps with a
// 302 whose Location is one of its OWN pages (most importantly login-actions/required-action —
// how KC 26 delivers a pending required action such as forced TOTP setup). Those
// absolute URLs need the same `/auth` splice the body rewrite does, or the browser lands on the
// gateway's SPA fallback instead of the Keycloak page (an MFA-required
// login would serve the shell's index.html instead of the TOTP-setup form). Redirects to
// NON-Keycloak URLs (the client's own redirect_uri /callback) must pass through untouched —
// /auth-splicing those would break every successful login.
func TestNewAuthProxy_RewritesLocationHeader(t *testing.T) {
	var wantLocation string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", wantLocation)
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := NewAuthProxy(target, false, nil)

	cases := []struct {
		name string
		loc  string
		want string
	}{
		{
			"keycloak-own page gains /auth",
			"https://gateway.example/realms/kiban/login-actions/required-action?execution=CONFIGURE_TOTP",
			"https://gateway.example/auth/realms/kiban/login-actions/required-action?execution=CONFIGURE_TOTP",
		},
		{
			"already-prefixed stays put",
			"https://gateway.example/auth/realms/kiban/login-actions/authenticate?x=1",
			"https://gateway.example/auth/realms/kiban/login-actions/authenticate?x=1",
		},
		{
			"client redirect_uri untouched",
			"https://gateway.example/callback?code=abc&state=x",
			"https://gateway.example/callback?code=abc&state=x",
		},
		{
			"foreign origin untouched",
			"https://elsewhere.example/realms/kiban/whatever",
			"https://elsewhere.example/realms/kiban/whatever",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantLocation = c.loc
			req := httptest.NewRequest(http.MethodGet, "/auth/realms/kiban/login-actions/authenticate", nil)
			req.Host = "gateway.example"
			req.TLS = &tls.ConnectionState{}
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)
			if got := rec.Header().Get("Location"); got != c.want {
				t.Errorf("Location = %q, want %q", got, c.want)
			}
		})
	}
}

// TestNewAuthProxy_ForgedHostPinnedToPublicOrigin proves the operator-cert topology
// (TrustProxyHeaders=false, KC_HOSTNAME_STRICT=false) no longer lets a client's Host header
// become Keycloak's self-URL host: Host/X-Forwarded-Host/-Proto reaching Keycloak are the
// configured issuer origin, whatever `Host` the request carried, and the body/Location rewrites
// splice /auth on that same pinned origin. Both the /auth and the verbatim mounts.
func TestNewAuthProxy_ForgedHostPinnedToPublicOrigin(t *testing.T) {
	var gotHost, gotXFHost, gotXFProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotXFHost, gotXFProto = r.Host, r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto")
		// What a KC_HOSTNAME_STRICT=false Keycloak renders: absolute URLs built from the
		// forwarded host it was handed.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":"%s://%s/realms/kiban"}`, gotXFProto, gotXFHost)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	origin, _ := url.Parse("https://kiban.example:8443/realms/kiban")

	for name, proxy := range map[string]http.Handler{
		"auth":     NewAuthProxy(target, false, origin),
		"verbatim": NewKeycloakVerbatimProxy(target, false, origin),
	} {
		t.Run(name, func(t *testing.T) {
			path := "/auth/realms/kiban/.well-known/openid-configuration"
			if name == "verbatim" {
				path = "/realms/kiban/.well-known/openid-configuration"
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = "evil.example"
			req.Header.Set("X-Forwarded-Host", "evil.example")
			req.Header.Set("X-Forwarded-Proto", "https")
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)

			if gotHost != "kiban.example:8443" || gotXFHost != "kiban.example:8443" || gotXFProto != "https" {
				t.Fatalf("backend saw Host=%q X-Forwarded-Host=%q X-Forwarded-Proto=%q, want the pinned kiban.example:8443/https", gotHost, gotXFHost, gotXFProto)
			}
			want := `"issuer":"https://kiban.example:8443/auth/realms/kiban"`
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("body = %s, want it to contain %s", rec.Body.String(), want)
			}
		})
	}
}
