// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/httpx"
)

// A confirmed authz denial is a 403 AUTHORIZATION_DENIED audited with
// authz's reason (distinct from the fail-closed 503), and registry's audit rows carry the
// request's correlation id.

type denyAuthorizer struct{ reason string }

func (d denyAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, &DeniedError{Reason: d.reason}
}

func newAuthzTestService(t *testing.T, authz AdminAuthorizer) *Service {
	t.Helper()
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	return NewService(NewStore(registryPool(t)), authz, auditWriter)
}

func TestHTTP_Enable_ConfirmedDenial_403AndAuditedWithReason(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)
	svc := newAuthzTestService(t, denyAuthorizer{reason: "PLATFORM_ROLE_REQUIRED"})

	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if errObj := decodeEnvelope(t, rec)["error"].(map[string]any); errObj["code"] != "AUTHORIZATION_DENIED" {
		t.Errorf("code = %v, want AUTHORIZATION_DENIED", errObj["code"])
	}

	var reason string
	err := admin.QueryRow(context.Background(), `
		SELECT payload->>'reason' FROM audit.registry__events
		WHERE subject = 'module:alpha' AND action = 'platform.module.enable' AND payload->>'denied' = 'true'
	`).Scan(&reason)
	if err != nil {
		t.Fatalf("query denial audit row: %v", err)
	}
	if reason != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("audited reason = %q, want PLATFORM_ROLE_REQUIRED", reason)
	}
	var enabled bool
	if err := admin.QueryRow(context.Background(), `SELECT enabled FROM platform.module_installation WHERE module_key = 'alpha'`).Scan(&enabled); err != nil {
		t.Fatalf("read installation: %v", err)
	}
	if enabled {
		t.Fatal("module was enabled despite the 403")
	}
}

func TestHTTP_Enable_AuditRowCarriesCorrelationID(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)
	svc := newAuthzTestService(t, allowAllAuthorizer{})

	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	req.Header.Set("x-correlation-id", "corr-registry-1")
	rec := httptest.NewRecorder()
	httpx.Correlation(svc.Routes()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var correlation *string
	err := admin.QueryRow(context.Background(), `
		SELECT correlation_id FROM audit.registry__events WHERE subject = 'module:alpha' AND action = 'platform.module.enable'
	`).Scan(&correlation)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if correlation == nil || *correlation != "corr-registry-1" {
		t.Fatalf("correlation_id = %v, want corr-registry-1", correlation)
	}
}
