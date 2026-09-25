// SPDX-License-Identifier: Apache-2.0

// The superadmin guard: requires AuthContext + raw bearer, calls authz effective-access/can
// for the platform-administration feature with a per-route action string; ANY
// error/uncertainty => 503 (fail-closed, never 401/allow); no caching; denials rely on
// authz-side audit.
package gateway

import (
	"context"
	"net/http"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/obs"
)

// adminResult is the guard's own tri-state read of authz's response: allowed, a confirmed
// denial (authzclient.Decision.Denied — the exact reasons the ScopeGlobal decision, evaluate.go
// steps 1-4, can produce), or uncertain (everything else, including transport errors, non-200 responses —
// which already includes authz's own DEPENDENCY_UNAVAILABLE => 503 mapping — and any
// unexpected/unparseable body). Uncertain is the fail-closed default: any case this type
// doesn't explicitly recognize as allowed or denied falls here, never through to allow.
type adminResult int

const (
	adminUncertain adminResult = iota
	adminAllowed
	adminDenied
)

// AuthzAdminClient calls authz's effective-access/can endpoint for the superadmin guard.
type AuthzAdminClient struct {
	inner *authzclient.AdminAuthorizer
}

// NewAuthzAdminClient builds a client against authz's base URL (e.g. http://127.0.0.1:8140).
func NewAuthzAdminClient(baseURL string) *AuthzAdminClient {
	return &AuthzAdminClient{inner: authzclient.New(baseURL, nil)}
}

// DecideAdmin calls POST {authzBaseURL}/internal/authz/effective-access/can for the
// superadmin feature, forwarding authorizationHeader verbatim (the actor is the bearer,
// never a body value — same rule internal/authz/http.go itself enforces) and the caller's
// per-route action string. See adminResult's doc for the fail-closed mapping.
func (c *AuthzAdminClient) DecideAdmin(ctx context.Context, authorizationHeader, action, correlationID string) adminResult {
	d, err := c.inner.Decide(ctx, authorizationHeader, action, correlationID)
	if err != nil {
		return adminUncertain
	}
	if d.Allowed && d.Reason == "ALLOWED" {
		return adminAllowed
	}
	if d.Denied() { // the shared client's confirmed-denial reason set (authzclient.Decision.Denied)
		return adminDenied
	}
	return adminUncertain
}

// RequireSuperadmin wraps next with the superadmin guard for one route, using action as
// this route's per-route action string. Must run downstream of RequireAuth (it reads the
// AuthContext RequireAuth attaches, and re-reads the raw Authorization header to forward
// verbatim — never a value derived from AuthContext, which never carries authority).
// A nil client (e.g. admin wiring not configured) fails closed exactly like a
// transport error would.
func RequireSuperadmin(client *AuthzAdminClient, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasAuth := AuthFromContext(r.Context())
			bearerHeader := r.Header.Get("Authorization")
			if client == nil || !hasAuth || bearerHeader == "" {
				writeAdminUnavailable(w)
				return
			}

			correlationID, _ := obs.CorrelationFromContext(r.Context())
			switch client.DecideAdmin(r.Context(), bearerHeader, action, correlationID) {
			case adminAllowed:
				next.ServeHTTP(w, r)
			case adminDenied:
				errenv.WriteError(w, http.StatusForbidden, errenv.APIError{
					Code:    errenv.CodeForbidden,
					Message: "superadministration requires superadmin access",
				})
			default: // adminUncertain — fail-closed, never 401/allow.
				writeAdminUnavailable(w)
			}
		})
	}
}

func writeAdminUnavailable(w http.ResponseWriter) {
	errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
		Code:    errenv.CodeAuthorizationUnavailable,
		Message: "superadministrator access could not be verified",
	})
}
