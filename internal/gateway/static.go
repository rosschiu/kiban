// SPDX-License-Identifier: Apache-2.0

// Static SPA/module-bundle serving + the `/internal/*` always-404 guard: `/` and
// unmatched non-API paths -> static file serving from KIBAN_STATIC_DIR (SPA fallback to
// index.html; module bundles under `/modules/<key>/` when present); `/internal/*` from
// outside => 404 always (internal APIs are never exposed at the edge).
package gateway

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rosschiu/kiban/internal/errenv"
)

// NewStaticHandler serves dir as the SPA/bundle tree: a request that resolves to a real,
// non-directory file under dir is served as-is; everything else (an unknown client-side route,
// or a bare directory — no directory listings, so a directory is never listed) falls
// back to dir/index.html. Module UI bundles need no special-casing here (no
// hardcoded module-name branches) — they are just files on disk under dir/modules/<key>/...,
// served by the same file server as everything else. r.URL.Path is cleaned with path.Clean
// before joining onto dir; for a rooted path (leading "/", which every http.Request.URL.Path
// is) that resolves any ".." segments to no more than the root itself, so fsPath can never
// escape dir.
func NewStaticHandler(dir string) http.Handler {
	fileServer := http.FileServer(http.Dir(dir))
	indexPath := filepath.Join(dir, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		fsPath := filepath.Join(dir, filepath.FromSlash(clean))

		if info, err := os.Stat(fsPath); err == nil && !info.IsDir() {
			// Vite writes content-hashed filenames under assets/ — safe to cache forever.
			// Every other real file (index.html requested directly, module bundles whose
			// hashing discipline we don't control) must revalidate on each use: without an
			// explicit Cache-Control, browsers heuristically cache on last-modified and keep
			// serving a pre-redeploy bundle (a stale index.html once kept
			// rendering an empty module nav long after the fix was deployed).
			if strings.HasPrefix(clean, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			if strings.HasSuffix(clean, ".html") {
				w.Header().Set("Content-Security-Policy", shellCSP)
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback: index.html is the one file that must never be served stale — it names
		// the hashed bundle entrypoints.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", shellCSP)
		http.ServeFile(w, r, indexPath)
	})
}

// shellCSP is the enforced Content-Security-Policy on the shell's HTML (index.html, whether
// requested directly or as the SPA fallback). Measured against the built bundle
// (web/shell/dist), not guessed:
//   - script-src 'self': index.html carries one external module script and no inline script;
//     no eval/new Function/Worker in the bundle.
//   - style-src 'self' 'unsafe-inline': the Tailwind stylesheet is external, but Radix's
//     Dialog/Sheet/DropdownMenu scroll lock (react-remove-scroll's style singleton) injects a
//     <style> element at open time — a nonce would need per-request HTML templating, and
//     inline STYLE cannot execute script. React's own style props go through CSSOM and are not
//     inline styles for CSP purposes.
//   - font-src 'self': Fira Sans is bundled under /assets (no data: fonts in the CSS).
//   - img-src 'self' data:: lucide icons are inline SVG elements; data: covers an ID-token
//     `picture` claim rendered by AvatarImage. No other image origin is fetched.
//   - connect-src 'self': the shell only ever talks to the gateway origin (web/shell/src/lib/
//     env.ts) — Keycloak is reached through the same-origin /auth proxy.
//   - frame-ancestors 'none' (the header twin of X-Frame-Options: DENY), base-uri 'self',
//     form-action 'self', object-src 'none': nothing in the shell frames, rebases, posts a
//     form, or embeds a plugin.
//
// Keycloak's own pages are proxied with Keycloak's own headers (securityHeaders skips them).
const shellCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; " +
	"base-uri 'self'; form-action 'self'; object-src 'none'"

// writeInternalNotFound is registered for `/internal/*` — internal service APIs are gateway-
// owned namespace that must never be reachable from outside the edge, regardless of whether
// anything is actually mounted there today. It also stands in for NewStaticHandler when no
// KIBAN_STATIC_DIR is configured (every unmatched path 404s instead of the gateway failing to
// start on a missing directory).
func writeInternalNotFound(w http.ResponseWriter, r *http.Request) {
	errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
		Code:    errenv.CodeNotFound,
		Message: "not found",
	})
}
