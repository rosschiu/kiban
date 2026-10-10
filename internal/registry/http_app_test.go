// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTP_RegisterApp(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	const key = "httpapp"
	cleanup := func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, key)
	}
	cleanup()
	t.Cleanup(cleanup)
	good := `{"key":"httpapp","displayName":"HTTP App","version":"1.0.0","serviceClientId":"httpapp-backend","features":["httpapp.view"],"authzFragment":{"httpapp_doc":{"company_module":{"this":true},"viewer":{"this":true}}}}`

	post := func(svc *Service, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/internal/platform/apps", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test")
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}

	t.Run("deny-all authorizer fails closed", func(t *testing.T) {
		if rec := post(newTestService(t), good); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
		}
	})
	svc := newAuthzTestService(t, allowAllAuthorizer{})
	t.Run("bad JSON is 400", func(t *testing.T) {
		if rec := post(svc, "{"); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("invalid manifest is 422", func(t *testing.T) {
		rec := post(svc, strings.Replace(good, `"httpapp-backend"`, `"Bad Client"`, 1))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("fragment without the company anchor is 422 and stores nothing", func(t *testing.T) {
		rec := post(svc, strings.Replace(good, `"company_module":{"this":true},`, ``, 1))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "company_module") {
			t.Fatalf("status = %d, want 422 naming company_module: %s", rec.Code, rec.Body.String())
		}
		var n int
		if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM authz.model_fragment WHERE module_key = $1`, key).Scan(&n); err != nil || n != 0 {
			t.Fatalf("model_fragment rows for %q = %d (%v), want 0: the registration must roll back", key, n, err)
		}
		if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM platform.app_registration WHERE module_key = $1`, key).Scan(&n); err != nil || n != 0 {
			t.Fatalf("app_registration rows for %q = %d (%v), want 0", key, n, err)
		}
	})
	t.Run("registered: installed, external, not enabled", func(t *testing.T) {
		rec := post(svc, good)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		data, _ := decodeEnvelope(t, rec)["data"].(map[string]any)
		if data["module"] != key || data["installed"] != true || data["enabled"] != false || data["external"] != true || data["serviceClientId"] != "httpapp-backend" {
			t.Fatalf("data = %v", data)
		}
	})
}
