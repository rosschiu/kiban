// SPDX-License-Identifier: Apache-2.0

// The real AdminAuthorizer (service.go's interface). registry's mutation endpoints (POST /internal/platform/modules/{key}/...)
// are only reachable via the compose-internal network — in practice always through the
// gateway's own superadmin guard (internal/gateway/superadmin.go), which has already
// confirmed the caller before proxying. EffectiveAccessAuthorizer is registry's OWN independent
// (defense-in-depth) confirmation of the exact same fact, calling authz directly rather than
// trusting the network boundary alone — a thin adapter over the shared internal/authz/client
// implementation, same as org and identity.
package registry

import (
	"context"
	"net/http"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
	"github.com/rosschiu/kiban/internal/obs"
)

// EffectiveAccessAuthorizer implements AdminAuthorizer by calling authz's
// POST /internal/authz/effective-access/can, forwarding authCtx.RawBearer verbatim (the ONLY
// value this type ever reads off authCtx — Subject is untouched, unused).
type EffectiveAccessAuthorizer struct {
	inner *authzclient.AdminAuthorizer
}

// NewEffectiveAccessAuthorizer builds the real AdminAuthorizer against authz's base URL
// (e.g. "http://authz:8140" in compose, "http://127.0.0.1:8140" for a host-run process).
func NewEffectiveAccessAuthorizer(baseURL string, client *http.Client) AdminAuthorizer {
	return &EffectiveAccessAuthorizer{inner: authzclient.New(baseURL, client)}
}

// Can reports true only for an explicit, well-formed ALLOWED response from authz. A confirmed
// denial (authzclient.Decision.Denied) is (false, *DeniedError) carrying authz's reason; every
// other outcome (missing bearer, transport error, non-200 status, malformed body, or a reason
// this type doesn't recognize) returns (false, ErrAuthorizationUnavailable) — fail-closed,
// matching the interface's own contract and gateway's identical guard.
func (a *EffectiveAccessAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	correlationID, _ := obs.CorrelationFromContext(ctx)
	d, err := a.inner.Decide(ctx, authCtx.RawBearer, action, correlationID)
	if err != nil {
		return false, ErrAuthorizationUnavailable
	}
	if d.Allowed && d.Reason == "ALLOWED" {
		return true, nil
	}
	if d.Denied() {
		return false, &DeniedError{Reason: d.Reason}
	}
	return false, ErrAuthorizationUnavailable
}
