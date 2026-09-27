// SPDX-License-Identifier: Apache-2.0

// Exposure pin: the gateway's `/auth/*` proxy (and the verbatim `/realms/*` mount) must never
// reach Keycloak's admin console/REST API or the master realm — those are operator surfaces
// bootstrap and scripts reach on Keycloak's own port, and the gateway's listener IS the public
// edge. The app realm keeps proxying.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/errenv"
)

func TestGateway_KeycloakAdminAndMasterRealmAreNotOnTheEdge(t *testing.T) {
	handler := buildTestRoutes(t) // the fake Keycloak answers 200 to everything it is asked

	blocked := []string{
		"/auth/admin",
		"/auth/admin/",
		"/auth/admin/master/console/",
		"/auth/admin/realms/kiban/users",
		"/auth/realms/master",
		"/auth/realms/master/",
		"/auth/realms/master/protocol/openid-connect/token",
		"/realms/master/protocol/openid-connect/token",
	}
	for _, path := range blocked {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, path, strings.NewReader(""))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), string(errenv.CodeNotFound)) {
				t.Errorf("%s %s: got %d %s, want the gateway's own 404 (never proxied to Keycloak)", method, path, rec.Code, rec.Body.String())
			}
		}
	}

	for _, path := range []string{
		"/auth/realms/kiban/protocol/openid-connect/token",
		"/auth/realms/kiban/.well-known/openid-configuration",
		"/realms/kiban/login-actions/reset-credentials",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: got %d, want 200 (app realm must still proxy)", path, rec.Code)
		}
	}
}
