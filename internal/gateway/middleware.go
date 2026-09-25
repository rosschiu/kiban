// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/modulekit"
)

type authContextKey struct{}

// ContextWithAuth / AuthFromContext thread the validated AuthContext through downstream
// handlers — the module proxy doesn't need it (Authorization is forwarded verbatim regardless
// of its contents), but the superadmin guard does (it requires the AuthContext plus the raw
// bearer).
func ContextWithAuth(ctx context.Context, authCtx AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, authCtx)
}

// AuthFromContext returns the AuthContext RequireAuth attached to ctx, if any.
func AuthFromContext(ctx context.Context) (AuthContext, bool) {
	v, ok := ctx.Value(authContextKey{}).(AuthContext)
	return v, ok
}

const userHeaderPrefix = "X-User-"

// hasUserHeader reports whether the request carries any inbound x-user-* header. These headers
// are gateway-injected only in the eventual per-request forwarding contract; accepting inbound
// x-user-* headers is barred outright — a client sending one is rejected, never
// silently stripped-and-forwarded (a silent strip would let a client probe for the header's
// existence via behavioral differences, and — more importantly — masks a caller that thinks
// it's authenticating itself via a header the gateway will never honor).
func hasUserHeader(h http.Header) bool {
	for name := range h {
		if len(name) >= len(userHeaderPrefix) && strings.EqualFold(name[:len(userHeaderPrefix)], userHeaderPrefix) {
			return true
		}
	}
	return false
}

// RequireAuth wraps next with bearer validation for /api/* routes. Any inbound x-user-* header
// is rejected 400 BEFORE token validation even runs. A missing or invalid bearer is
// rejected 401 with WWW-Authenticate: Bearer. A valid bearer whose subject this process has not
// yet provisioned (Provisioner) is resolved through identity first — 503
// AUTHORIZATION_UNAVAILABLE if that fails (fail closed). On success the validated AuthContext is
// attached to the request context for downstream handlers. prov is nil only in tests that
// exercise other layers; Routes always wires one.
func RequireAuth(verifier *TokenVerifier, prov *Provisioner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hasUserHeader(r.Header) {
				errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
					Code:    errenv.CodeBadRequest,
					Message: "x-user-* headers are gateway-internal and may not be set by clients",
				})
				return
			}

			bearer := bearerFromHeader(r.Header.Get("Authorization"))
			authCtx, err := verifier.Verify(r.Context(), bearer)
			if err != nil {
				code := errenv.CodeAuthTokenInvalid
				if errors.Is(err, ErrTokenMissing) {
					code = errenv.CodeAuthTokenMissing
				}
				w.Header().Set("WWW-Authenticate", "Bearer")
				errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{
					Code:    code,
					Message: "authentication required",
				})
				return
			}

			if prov != nil {
				if err := prov.Ensure(r.Context(), authCtx.Subject, r.Header.Get("Authorization")); err != nil {
					errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
						Code:    errenv.CodeAuthorizationUnavailable,
						Message: "identity provisioning is unavailable",
					})
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ContextWithAuth(r.Context(), authCtx)))
		})
	}
}

func bearerFromHeader(v string) string {
	return modulekit.BearerFromHeader(v)
}
