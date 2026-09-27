// SPDX-License-Identifier: Apache-2.0

// `/auth/*` — reverse proxy to Keycloak: path-prefix strip, websocket-safe, no auth required.
// `/resources/*` and `/realms/*` — same target, no prefix strip, no Set-Cookie Path
// rewrite (NewKeycloakVerbatimProxy, below) — see routes.go's wiring and that function's comment.
package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

// NewAuthProxy reverse-proxies everything under `/auth/` to target (Keycloak's own base URL),
// stripping the `/auth` prefix. Keycloak itself keeps its default http-relative-path ("/") —
// this needs no realm-file or hostname config change at all (stripping the prefix at the
// gateway needs neither KC_HTTP_RELATIVE_PATH nor the hostname options touched). No bearer auth
// is required on this path — it is
// never wrapped in RequireAuth. httputil.ReverseProxy forwards HTTP Upgrade (websocket) requests
// natively (stdlib behavior since Go 1.12: it detects `Connection: Upgrade` and switches to a
// bidirectional byte-copy via Hijacker) — no extra code is needed for websocket-safety.
//
// Host header: this must NOT set `pr.Out.Host = target.Host` (Keycloak's internal
// container address, e.g. "keycloak:8080"), which — combined with KC_HOSTNAME_STRICT=false and
// no KC_PROXY_HEADERS — made Keycloak's non-strict hostname resolution read that internal Host
// header and generate every absolute URL in its rendered pages (crucially, the login form's own
// `action` URL) pointing at "keycloak:8080", a host only reachable from inside the compose
// network, never from a browser or any client outside it. Every interactive browser login would
// break at the password-submit step (the login PAGE renders fine; the FORM POST has nowhere
// reachable to go). Instead, leave the
// outbound Host header as the ORIGINAL external one the client actually used, and also carry it
// via X-Forwarded-Host/-Proto/-For (SetXForwarded) for infra/compose.yaml's paired
// KC_PROXY_HEADERS=xforwarded to trust — target.Host is still used for the actual TCP dial via
// pr.Out.URL.Host, so routing to the real Keycloak container is unaffected.
//
// That alone fixed the HOST, but not the PATH: Keycloak itself still runs at its default
// http-relative-path ("/", per this func's own top comment — changing that is deliberately
// avoided, since KC_HTTP_RELATIVE_PATH governs EVERY path Keycloak serves, including the ones
// bootstrap/tests reach directly on its own published port, bypassing this proxy entirely; a
// global relative-path change would ripple far past this proxy). So every same-origin absolute
// URL Keycloak renders into its own pages (the login form's `action`, most visibly) now has the
// right host but is still missing this proxy's own `/auth` prefix — a browser POSTing to that
// `action` verbatim 404s at this gateway's edge, one hop short of Keycloak. rewriteAuthOrigin
// (ModifyResponse) patches exactly that: for textual bodies, every occurrence of the external
// origin THIS request itself was reached at (from the X-Forwarded-Host/-Proto SetXForwarded
// just set) gets `/auth` spliced in right after it, so Keycloak's self-referencing links resolve
// back through this same proxy instead of 404ing one segment short of it.
//
// Body rewriting alone still wasn't enough: Keycloak's login flow ALSO sets a `Path`-scoped
// session cookie (KC_RESTART, AUTH_SESSION_ID) computed from the STRIPPED path it actually saw
// (e.g. `Path=/realms/kiban/`, no `/auth`) — a later request to the real, `/auth`-prefixed path
// (`/auth/realms/kiban/login-actions/authenticate`) doesn't match that cookie's Path per RFC
// 6265 §5.1.4, so the browser/client never sends it back, and Keycloak's own login-actions
// endpoint then fails with "Restart login cookie not found" (reproducible with a
// bare cookie-jar curl round trip). rewriteSetCookiePaths (same ModifyResponse call) prefixes `/auth`
// onto every Set-Cookie response header's own Path attribute for the identical reason.
// trustForwardedHeaders exists for the one topology SetXForwarded gets wrong: TLS terminated a
// hop EARLIER than this gateway (public shared-Traefik mode, infra/compose.public.yaml). There
// the gateway is reached over plain HTTP, so SetXForwarded derives X-Forwarded-Proto=http —
// clobbering the edge's correct `https` before Keycloak (sslRequired) or rewriteAuthOrigin
// (which matches on that same origin string) sees it; the login form's action then goes out
// un-rewritten and the browser's POST 404s one hop short of Keycloak. When true, inbound
// X-Forwarded-Proto/-Host are passed
// through instead of self-derived. Only ever set it behind an edge that overwrites these
// headers itself (Traefik does) — trusting them from arbitrary clients would let a caller spoof
// its origin. Wired to KIBAN_TRUSTED_PROXY (default false).
//
// publicOrigin pins the topology WITHOUT a trusted edge (compose.yaml: the gateway's own TLS
// listener, KC_HOSTNAME_STRICT=false): there SetXForwarded would derive X-Forwarded-Host from
// the CLIENT's Host header, and Keycloak would build every self-URL — the discovery `issuer`,
// the login form's action, e-mail action links — from whatever Host an attacker sent. Instead
// Host/X-Forwarded-Host/-Proto are forced to publicOrigin: the issuer URL every token verifier
// already requires `iss` to equal (KEYCLOAK_ISSUER_URL), so a token minted for any other host
// was never going to validate anyway. nil (tests) keeps the self-derived headers.
func NewAuthProxy(target *url.URL, trustForwardedHeaders bool, publicOrigin *url.URL) http.Handler {
	return newKeycloakProxy(target, trustForwardedHeaders, publicOrigin, true /* stripAuthPrefix */, true /* rewriteCookiePaths */)
}

// NewKeycloakVerbatimProxy backs the `/resources/` and `/realms/` gateway routes: the
// SAME Keycloak target and response-rewrite pipeline as NewAuthProxy (rewriteAuthOrigin,
// rewriteLocationHeader — Keycloak's absolute self-referencing URLs still need the `/auth`
// splice so they keep resolving through the `/auth` proxy), but two
// differences from NewAuthProxy, both because these routes carry no `/auth` prefix at all —
// Keycloak's own root-relative references (`/resources/...` theme assets, `/realms/...`
// Forgot-Password/action-page links) resolve directly at THIS path once it's mounted, which is
// the whole point of these mounts:
//
//  1. No prefix is stripped — the inbound path (already `/resources/...` or `/realms/...`) is
//     forwarded to Keycloak verbatim; Keycloak itself still runs at relative-path "/", so this
//     already matches what it expects (same reasoning as NewAuthProxy's own stripped path).
//  2. Set-Cookie `Path` attributes are left UNTOUCHED (rewriteSetCookiePaths is skipped).
//     Proven with a cookie-jar test (auth_proxy_live_test.go's
//     TestLive_KeycloakVerbatimProxy_CookieJar): a session cookie Keycloak scopes to
//     `Path=/realms/kiban/` while being served THROUGH THIS ROUTE must keep that exact Path —
//     prefixing `/auth` (NewAuthProxy's behavior) would scope it to `/auth/realms/kiban/`, which
//     RFC 6265 §5.1.4's path-match rule never sends back to a follow-up request that stays on
//     the un-prefixed `/realms/kiban/...` path this same flow continues on (the browser is
//     ACTUALLY on `/realms/...`, never `/auth/realms/...`, for anything reaching this handler) —
//     reproducing the identical "Restart login cookie not found" class of bug NewAuthProxy's own
//     rewriteSetCookiePaths was built to fix for the `/auth`-prefixed path, just mirrored: the
//     fix there was ADDING the prefix to match a request path that HAS it; here it's never
//     adding one, to match a request path that never does.
func NewKeycloakVerbatimProxy(target *url.URL, trustForwardedHeaders bool, publicOrigin *url.URL) http.Handler {
	return newKeycloakProxy(target, trustForwardedHeaders, publicOrigin, false /* stripAuthPrefix */, false /* rewriteCookiePaths */)
}

func newKeycloakProxy(target *url.URL, trustForwardedHeaders bool, publicOrigin *url.URL, stripAuthPrefix, rewriteCookiePaths bool) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			copyForwardedFor(pr)
			switch {
			case trustForwardedHeaders:
				for _, h := range []string{"X-Forwarded-Proto", "X-Forwarded-Host"} {
					if v := firstForwardedValue(pr.In.Header.Get(h)); v != "" {
						pr.Out.Header.Set(h, v)
					}
				}
			case publicOrigin != nil:
				pr.Out.Host = publicOrigin.Host
				pr.Out.Header.Set("X-Forwarded-Host", publicOrigin.Host)
				pr.Out.Header.Set("X-Forwarded-Proto", publicOrigin.Scheme)
			}

			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host

			if stripAuthPrefix {
				rest := strings.TrimPrefix(pr.In.URL.Path, "/auth")
				if rest == "" {
					rest = "/"
				}
				pr.Out.URL.Path = rest
				pr.Out.URL.RawPath = ""
			}
			// else: pr.Out.URL.Path already equals pr.In.URL.Path (ReverseProxy seeds pr.Out as a
			// clone of pr.In before calling Rewrite) — exactly the verbatim forward this variant
			// needs, no further edit required.
		},
		ModifyResponse: func(resp *http.Response) error {
			if rewriteCookiePaths {
				rewriteSetCookiePaths(resp)
			}
			rewriteLocationHeader(resp)
			if err := rewriteAuthOrigin(resp); err != nil {
				return err
			}
			if stripAuthPrefix {
				// Only on the /auth mount — see rewriteRootRelativeRealmsLinks's
				// own comment for why the verbatim mount must NOT do this too.
				return rewriteRootRelativeRealmsLinks(resp)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProxyError(w, err, "keycloak unreachable")
		},
	}
}

// rewriteLocationHeader splices `/auth` into a redirect Location that points at one of
// KEYCLOAK'S OWN pages at this proxy's external origin (path under /realms/ or /resources/) —
// the header-side twin of rewriteAuthOrigin's body rewrite. Keycloak 26 delivers pending
// required actions (forced TOTP setup, most visibly) as a 302 to its own
// login-actions/required-action URL; un-spliced, that Location resolves to the gateway's SPA
// fallback and the browser gets the shell instead of the Keycloak page.
// Redirects to anything else — above all the OIDC client's own redirect_uri (/callback), the
// success shape of every login — pass through byte-for-byte.
func rewriteLocationHeader(resp *http.Response) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	xfProto := resp.Request.Header.Get("X-Forwarded-Proto")
	xfHost := resp.Request.Header.Get("X-Forwarded-Host")
	if xfProto == "" || xfHost == "" {
		return
	}
	origin := xfProto + "://" + xfHost
	for _, kcPath := range []string{"/realms/", "/resources/"} {
		if strings.HasPrefix(loc, origin+kcPath) {
			resp.Header.Set("Location", origin+"/auth"+strings.TrimPrefix(loc, origin))
			return
		}
	}
}

// firstForwardedValue reduces a possibly comma-joined X-Forwarded-* value (RFC 7239-style
// multi-hop appending) to its first (client-most) element — the only one the next hop should
// re-assert.
func firstForwardedValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// textualContentTypes are the response Content-Types worth scanning for self-referencing
// origin URLs — Keycloak's login/error/info pages (text/html), its OIDC discovery document and
// JSON error bodies (application/json), and its JWKS document (application/jwk-set+json, which
// carries no URLs today but costs nothing to include). Binary/asset responses (CSS, JS, images
// under /resources/*) are skipped entirely — they're either not affected or too large/costly to
// scan for no benefit.
var textualContentTypes = []string{"text/html", "application/json", "application/jwk-set+json"}

// rewriteSetCookiePaths prefixes `/auth` onto every Set-Cookie response header's own `Path`
// attribute (adding one scoped to `/auth/` if a header has none) — see NewAuthProxy's own
// comment for the full "why". String-level rewriting, not a full RFC 6265 cookie
// parse-then-reserialize, so every other attribute (Secure, HttpOnly, SameSite, Max-Age, the
// cookie's own value) survives byte-for-byte.
func rewriteSetCookiePaths(resp *http.Response) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}
	rewritten := make([]string, len(cookies))
	for i, c := range cookies {
		rewritten[i] = prefixCookiePath(c)
	}
	resp.Header["Set-Cookie"] = rewritten
}

func prefixCookiePath(setCookie string) string {
	parts := strings.Split(setCookie, ";")
	for i, p := range parts {
		trimmed := strings.TrimSpace(p)
		if len(trimmed) < 5 || !strings.EqualFold(trimmed[:5], "path=") {
			continue
		}
		path := trimmed[5:]
		if strings.HasPrefix(path, "/auth") {
			return setCookie // already prefixed (idempotent — a second proxy hop, if any)
		}
		if path == "/" {
			path = "/auth/"
		} else {
			path = "/auth" + path
		}
		parts[i] = " Path=" + path
		return strings.Join(parts, ";")
	}
	// No Path attribute at all: Keycloak always sets one for its own session cookies, but don't
	// assume that holds for every response — add one scoped to /auth rather than let the
	// browser default it to the (also `/auth`-missing) request path.
	return setCookie + "; Path=/auth/"
}

// isTextualResponse reports whether resp's Content-Type is one of textualContentTypes — the
// shared gate both rewriteAuthOrigin and rewriteRootRelativeRealmsLinks use before paying for a
// full body read; binary/asset responses (CSS, JS, images) skip both untouched.
func isTextualResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	for _, want := range textualContentTypes {
		if strings.HasPrefix(ct, want) {
			return true
		}
	}
	return false
}

// rewriteAuthOrigin patches Keycloak's self-referencing absolute URLs (the login form's
// `action`, the session-restart script URL, discovery-document endpoint URLs, ...) so they
// resolve back through this gateway's `/auth` prefix instead of one path segment short of it.
// See NewAuthProxy's own comment for the full "why".
func rewriteAuthOrigin(resp *http.Response) error {
	if !isTextualResponse(resp) {
		return nil
	}

	xfProto := resp.Request.Header.Get("X-Forwarded-Proto")
	xfHost := resp.Request.Header.Get("X-Forwarded-Host")
	if xfProto == "" || xfHost == "" {
		return nil
	}
	origin := xfProto + "://" + xfHost

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	rewritten := strings.ReplaceAll(string(body), origin+"/", origin+"/auth/")
	resp.Body = io.NopCloser(bytes.NewReader([]byte(rewritten)))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return nil
}

// rewriteRootRelativeRealmsLinks fixes a residual cookie-continuity gap the live cookie-jar
// test (auth_proxy_live_test.go's TestLive_KeycloakVerbatimProxy_CookieJar) surfaced but
// doesn't itself cover: rewriteAuthOrigin
// only splices `/auth` into absolute self-referencing URLs (origin+path). Some of Keycloak's own
// links are ROOT-RELATIVE instead — no origin at all — most visibly the login page's own
// Forgot-Password link (`href="/realms/{realm}/login-actions/reset-credentials?..."`, carrying
// `tab_id`/`client_data` tied to the auth session Keycloak just started). A browser resolves a
// root-relative href against the site ROOT, not the current page's path, so clicking it drops
// the `/auth` prefix entirely and lands on the verbatim `/realms/` mount — which DOES
// reach Keycloak (no SPA-fallback shell), but the session cookie the
// login page established carries `Path=/auth/realms/{realm}/` (NewAuthProxy's own
// rewriteSetCookiePaths), a Path RFC 6265 §5.1.4 never sends on a request to the un-prefixed
// `/realms/...` path — Keycloak then fails with its own "Restart login cookie not found"
// error (reproducible with a bare cookie-jar curl round trip). Splicing `/auth` onto these root-
// relative links too keeps the browser on the SAME mount (and therefore the SAME cookie Path)
// for the whole flow, exactly mirroring what rewriteAuthOrigin already does for absolute links.
//
// Only ever used on the `/auth`-mounted proxy (stripAuthPrefix=true) — running it on the
// verbatim `/resources//realms` mount's OWN responses would recreate the identical mismatch in
// reverse: a page reached bare (Path=/realms/{realm}/... cookie) linking onward to an
// `/auth`-scoped path its own cookie doesn't cover.
//
// String-level, scoped to the `="/realms/` attribute-value shape (matches href=, src=, action=,
// and formaction= alike; already-`/auth`-prefixed or absolute occurrences never contain this
// exact substring, so the rewrite is naturally idempotent) — a full HTML parse is unwarranted for
// one fixed literal, the same reasoning prefixCookiePath's own attribute-level rewrite uses.
// `/resources/*` root-relative references are deliberately left untouched: those assets are
// stateless (no cookie dependency) and already resolve correctly, unrewritten, at the
// verbatim `/resources/` mount.
func rewriteRootRelativeRealmsLinks(resp *http.Response) error {
	if !isTextualResponse(resp) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	rewritten := strings.ReplaceAll(string(body), `="/realms/`, `="/auth/realms/`)
	resp.Body = io.NopCloser(bytes.NewReader([]byte(rewritten)))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return nil
}
