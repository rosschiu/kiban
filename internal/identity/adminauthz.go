// SPDX-License-Identifier: Apache-2.0

// The real AdminAuthorizer, replacing denyAllAuthorizer in production. Same shared
// implementation as internal/org/adminauthz.go — see that file's doc comment for why this is a
// thin adapter over internal/authz/client rather than a third copy of the HTTP logic.
package identity

import (
	"context"
	"net/http"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
	"github.com/rosschiu/kiban/internal/obs"
)

// engineAdminAuthorizer adapts authzclient.AdminAuthorizer to this package's AdminAuthorizer
// interface (which names identity's own AuthContext type).
type engineAdminAuthorizer struct {
	inner *authzclient.AdminAuthorizer
}

// Can forwards authCtx.RawBearer (and the request's correlation id) to authz's
// effective-access/can (scope=global, requiredPlatformRole="kiban-superadmin") via the shared
// client. An ALLOWED envelope is (true, nil); a confirmed denial (authzclient.Decision.Denied)
// is (false, *DeniedError) carrying authz's reason; everything else is (false,
// ErrAuthorizationUnavailable) — fail-closed.
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

// NewEngineAdminAuthorizer returns the real, authz-service-backed AdminAuthorizer.
func NewEngineAdminAuthorizer(baseURL string, httpClient *http.Client) AdminAuthorizer {
	return engineAdminAuthorizer{inner: authzclient.New(baseURL, httpClient)}
}
