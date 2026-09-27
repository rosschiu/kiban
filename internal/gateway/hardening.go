// SPDX-License-Identifier: Apache-2.0

// Edge hardening: server/read/write timeouts, 1MB default body limit on
// gateway-handled routes (proxied module bodies limited 32MB), header hygiene (strip
// hop-by-hop), no directory listings, security response headers, and the edge's own view of the
// client address (X-Forwarded-For). Server/read/write timeouts are set on the http.Server in
// cmd/gateway; "no directory listings" is static.go's own design (a directory never reaches
// http.FileServer). Hop-by-hop hygiene needs no code here: net/http/httputil.ReverseProxy already
// strips RFC 7230 hop-by-hop headers (Connection, Keep-Alive, Proxy-Authenticate,
// Proxy-Authorization, TE, Trailer, Transfer-Encoding, Upgrade — plus anything named by an
// inbound Connection header) from both the outbound request and the returned response,
// unconditionally, for every proxy this package builds (module, platform, auth) — confirmed by
// reading net/http/httputil/reverseproxy.go's own ServeHTTP.
package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/rosschiu/kiban/internal/errenv"
)

const (
	// defaultBodyLimit applies to every gateway-handled route except the dynamic module proxy.
	defaultBodyLimit int64 = 1 << 20 // 1MB
	// moduleProxyBodyLimit is the larger allowance for module API traffic — the one exception
	// to the 1MB default.
	moduleProxyBodyLimit int64 = 32 << 20 // 32MB
)

// limitBody wraps next so r.Body is capped at limit bytes (http.MaxBytesReader — reading past
// the limit fails the request with an error the handler/proxy surfaces as its own read
// failure). GET/HEAD requests typically carry no body at all; wrapping them is harmless (there
// is nothing to read past the limit).
func limitBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// writeProxyError is the shared ReverseProxy ErrorHandler body: a request body that overran
// limitBody's cap (http.MaxBytesError surfaces through the transport's outbound copy) is the
// CLIENT's fault — 413 PAYLOAD_TOO_LARGE — never the upstream's; everything else (dial refused,
// response-header timeout, ...) is the 503 MODULE_UNAVAILABLE the caller names. Returns true
// when the error was the body cap, so the module proxy can keep it out of the upstream metric.
func writeProxyError(w http.ResponseWriter, err error, unavailableMessage string) (tooLarge bool) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		errenv.WriteError(w, http.StatusRequestEntityTooLarge, errenv.APIError{
			Code:    errenv.CodePayloadTooLarge,
			Message: "request body too large",
		})
		return true
	}
	errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
		Code:    errenv.CodeModuleUnavailable,
		Message: unavailableMessage,
	})
	return false
}

// keycloakPrefixes are the mounts whose responses come from Keycloak itself (auth_proxy.go):
// Keycloak sets its own security headers and answers CORS itself, so neither securityHeaders nor
// CORS touches them (cors.go's corsExemptPrefixes reuses this list).
var keycloakPrefixes = []string{"/auth/", "/realms/", "/resources/"}

func hasKeycloakPrefix(path string) bool {
	for _, p := range keycloakPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// securityHeaders sets the baseline security response headers on every gateway-originated
// response (static shell, the gateway's own JSON errors, proxied module/foundation responses)
// except the Keycloak mounts. They are set at WriteHeader time through a ResponseWriter wrapper
// (not up front on w.Header()) so an upstream that already sends one of them is overridden
// rather than duplicated (ReverseProxy copies upstream headers with Add). HSTS only when this
// request was actually served over TLS — the gateway's own listener, or (when trustProxy) a
// TLS-terminating edge in front that asserts X-Forwarded-Proto: https — never on plain HTTP,
// where the browser would ignore it anyway and a dev stack must not pin itself to https.
// The shell's Content-Security-Policy is static.go's (only the HTML needs one).
func securityHeaders(trustProxy bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasKeycloakPrefix(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		hsts := r.TLS != nil || (trustProxy && firstForwardedValue(r.Header.Get("X-Forwarded-Proto")) == "https")
		next.ServeHTTP(&securityHeaderWriter{ResponseWriter: w, hsts: hsts}, r)
	})
}

type securityHeaderWriter struct {
	http.ResponseWriter
	hsts  bool
	wrote bool
}

func (s *securityHeaderWriter) WriteHeader(status int) {
	if !s.wrote {
		s.wrote = true
		h := s.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if s.hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *securityHeaderWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Flush/Unwrap keep streaming (ReverseProxy's flush) and http.ResponseController's Hijack
// (websockets) reaching the real writer — the same contract httpx.StatusRecorder documents.
func (s *securityHeaderWriter) Flush() {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *securityHeaderWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// clientForwardedFor rewrites the inbound X-Forwarded-For to the EDGE's view of the client
// before any proxy sees it: the peer IP is appended; whatever the client sent is kept only when
// trustProxy (a TLS-terminating edge in front that overwrites the header itself) and dropped
// otherwise. Every proxy's Rewrite then copies the header out verbatim (copyForwardedFor) —
// httputil.ReverseProxy strips inbound X-Forwarded-* from pr.Out before calling Rewrite.
func clientForwardedFor(trustProxy bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prior := ""
		if trustProxy {
			prior = strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		}
		r.Header.Del("X-Forwarded-For")
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if prior != "" {
				ip = prior + ", " + ip
			}
			r.Header.Set("X-Forwarded-For", ip)
		} else if prior != "" {
			r.Header.Set("X-Forwarded-For", prior)
		}
		next.ServeHTTP(w, r)
	})
}

// copyForwardedFor forwards the X-Forwarded-For clientForwardedFor computed — called from every
// proxy's Rewrite, after any SetXForwarded (which would otherwise re-derive it from the peer
// alone).
func copyForwardedFor(pr *httputil.ProxyRequest) {
	if v := pr.In.Header.Get("X-Forwarded-For"); v != "" {
		pr.Out.Header.Set("X-Forwarded-For", v)
	}
}
