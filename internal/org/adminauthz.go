// SPDX-License-Identifier: Apache-2.0

// The production AdminAuthorizer. org has no engine-relation question to ask here — "may this
// caller administer org" is exactly the same platform-superadmin global-scope question registry's
// own EffectiveAccessAuthorizer (internal/registry/adminauthz.go) already answers, so this is a
// thin adapter over the shared internal/authz/client implementation rather than a second copy of
// the HTTP logic.
package org

import (
	"context"
	"net/http"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
	"github.com/rosschiu/kiban/internal/obs"
)

// engineAdminAuthorizer adapts authzclient.AdminAuthorizer to this package's AdminAuthorizer
// interface (which names org's own AuthContext type, so Go can't satisfy it structurally without
// this one-method wrapper).
type engineAdminAuthorizer struct {
	inner *authzclient.AdminAuthorizer
}

// Can forwards authCtx.RawBearer (and the request's correlation id) to authz's
// effective-access/can (scope=global, requiredPlatformRole="kiban-superadmin") via the shared
// client. An ALLOWED envelope is (true, nil); a confirmed denial (authzclient.Decision.Denied)
// is (false, *DeniedError) carrying authz's reason; everything else is (false,
// ErrAuthorizationUnavailable) — THIS package's sentinel, which the HTTP layer's 503 mapping
// keys off.
func (a engineAdminAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
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

// NewEngineAdminAuthorizer returns the real, authz-service-backed AdminAuthorizer: fails closed
// (ErrAuthorizationUnavailable) on anything but an explicit ALLOWED response from authz — same
// seam denyAllAuthorizer defined, now backed by a live decision instead of an unconditional 503.
func NewEngineAdminAuthorizer(baseURL string, httpClient *http.Client) AdminAuthorizer {
	return engineAdminAuthorizer{inner: authzclient.New(baseURL, httpClient)}
}
