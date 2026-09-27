// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Checks are restricted to the feature keys a module declares (plus the synthesized
// "<key>.access"); a module that declares none is not restricted.
func TestHandleCan_AppFeatureDeclared(t *testing.T) {
	const app, builtin, sub = "hf-app", "hf-builtin", "hf-user"
	companyID := uuid.NewString()
	fakeAppOwners = map[string]string{app: "hf-app-backend"}
	fakeAppFeatures = map[string][]string{app: {"hf-app.ticket.view"}}
	t.Cleanup(func() { fakeAppOwners = map[string]string{}; fakeAppFeatures = map[string][]string{} })

	svc, issuer, _ := buildHTTPService(t,
		map[string][]string{sub: nil},
		map[string]bool{app: true, builtin: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{companyID + "/" + sub: {isMember: true, active: true}},
		false,
	)
	can := func(path, module, feature string) *httptest.ResponseRecorder {
		body := map[string]any{"featureKey": feature, "moduleKey": module, "scope": "company", "companyId": companyID}
		if path == "/internal/authz/effective-access/batch-can" {
			body["items"] = []map[string]any{{"object": map[string]string{"type": "company", "id": companyID}, "relation": "member"}}
		}
		req := httptest.NewRequest(http.MethodPost, path, mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, sub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}
	for _, path := range []string{"/internal/authz/effective-access/can", "/internal/authz/effective-access/batch-can"} {
		if rec := can(path, app, "hf-app.ticket.view"); rec.Code != http.StatusOK {
			t.Errorf("%s declared feature: status %d: %s", path, rec.Code, rec.Body.String())
		}
		if rec := can(path, app, "hf-app.access"); rec.Code != http.StatusOK {
			t.Errorf("%s synthesized access feature: status %d: %s", path, rec.Code, rec.Body.String())
		}
		if rec := can(path, app, "hf-app.ticket.delete"); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s undeclared feature: status %d, want 422: %s", path, rec.Code, rec.Body.String())
		}
		if rec := can(path, builtin, "hf-builtin.anything"); rec.Code != http.StatusOK {
			t.Errorf("%s module declaring no features is unrestricted: status %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}
