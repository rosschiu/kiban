// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	store := NewStore(registryPool(t))
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	return NewService(store, NewDenyAllAuthorizer(), auditWriter)
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body not valid JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

func TestHTTP_CapabilitiesAll_Envelope(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, true)

	svc := newTestService(t)
	req := httptest.NewRequest(http.MethodGet, "/api/platform/capabilities", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("expected data array, got %v", body)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 capability, got %d: %v", len(data), data)
	}
}

func TestHTTP_CapabilityOne_NotFound(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	svc := newTestService(t)
	req := httptest.NewRequest(http.MethodGet, "/api/platform/capabilities/ghost", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", body)
	}
	if errObj["code"] != "NOT_FOUND" {
		t.Errorf("code = %v, want NOT_FOUND", errObj["code"])
	}
}

func TestHTTP_Catalog(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)

	svc := newTestService(t)
	req := httptest.NewRequest(http.MethodGet, "/api/platform/catalog", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data, ok := body["data"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected 1 catalog entry, got %v", body)
	}
}

// TestHTTP_Enable_FailClosed503AndAudited proves the denyAllAuthorizer path: a mutation is
// refused with 503 AUTHORIZATION_UNAVAILABLE (never a silent allow), and the denial itself is
// audited — asserted by reading the row back in the same test.
func TestHTTP_Enable_FailClosed503AndAudited(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)

	svc := newTestService(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", body)
	}
	if errObj["code"] != "AUTHORIZATION_UNAVAILABLE" {
		t.Errorf("code = %v, want AUTHORIZATION_UNAVAILABLE", errObj["code"])
	}

	// The mutation must NOT have taken effect (fail-closed, not a partial allow).
	cap, code, err := svc.store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("capability lookup: %v", err)
	}
	if cap.Enabled {
		t.Errorf("module was enabled despite the 503 fail-closed guard: %+v", cap)
	}
	if code == "" {
		t.Errorf("expected a non-ok capability code after a refused enable, got \"\"")
	}

	var count int
	err = admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.registry__events
		WHERE subject = 'module:alpha' AND action = 'platform.module.enable'
		  AND payload->>'denied' = 'true'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 denial audit row, got %d", count)
	}
}

func TestHTTP_Disable_MandatoryModuleWouldBe422_IfAuthorized(t *testing.T) {
	// denyAllAuthorizer always intercepts before validation, so the 422 mandatory-module
	// path is exercised directly against the store here (the HTTP path to it is identical with
	// a real authorizer — see service.go).
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "spine", true)
	insertInstallationFixture(t, admin, "spine", true, true)

	store := NewStore(registryPool(t))
	_, err := store.SetEnabled(context.Background(), "spine", false, nil)
	if err == nil {
		t.Fatal("expected ErrMandatoryModule, got nil")
	}
	if !errors.Is(err, ErrMandatoryModule) {
		t.Errorf("err = %v, want %v", err, ErrMandatoryModule)
	}
}

func TestHTTP_HealthAndReady(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	svc := newTestService(t)

	for _, path := range []string{"/health", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200, body=%s", path, rec.Code, rec.Body.String())
		}
	}
}
