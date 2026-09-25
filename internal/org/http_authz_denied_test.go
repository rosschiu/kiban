// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/httpx"
)

// A confirmed authz denial is a 403 AUTHORIZATION_DENIED audited with
// authz's reason (distinct from the fail-closed 503), and org's audit rows carry the request's
// correlation id.

type denyAuthorizer struct{ reason string }

func (d denyAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, &DeniedError{Reason: d.reason}
}

func TestHTTP_CreateUnit_ConfirmedDenial_403AndAuditedWithReason(t *testing.T) {
	f := newHTTPTestFixture(t)
	f.svc.authz = denyAuthorizer{reason: "PLATFORM_ROLE_REQUIRED"}
	admin := adminPool(t)

	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"DENIED1","name":"Denied"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
	if errObj["code"] != "AUTHORIZATION_DENIED" {
		t.Errorf("code = %v, want AUTHORIZATION_DENIED", errObj["code"])
	}

	var reason string
	err := admin.QueryRow(context.Background(), `
		SELECT payload->>'reason' FROM audit.org__events
		WHERE subject = 'org_unit:new' AND action = 'org.unit.create' AND payload->>'denied' = 'true'
	`).Scan(&reason)
	if err != nil {
		t.Fatalf("query denial audit row: %v", err)
	}
	if reason != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("audited reason = %q, want PLATFORM_ROLE_REQUIRED", reason)
	}
	var unitCount int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM org.org_unit WHERE code = 'DENIED1'`).Scan(&unitCount); err != nil {
		t.Fatalf("count units: %v", err)
	}
	if unitCount != 0 {
		t.Fatal("unit was created despite the 403")
	}
}

func TestHTTP_CreateUnit_AuditRowCarriesCorrelationID(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	admin := adminPool(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/org/units", strings.NewReader(`{"typeKey":"company","code":"corr1","name":"Corr One"}`))
	req.Header.Set("x-correlation-id", "corr-org-1")
	rec := httptest.NewRecorder()
	httpx.Correlation(f.svc.Routes()).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var correlation *string
	err := admin.QueryRow(context.Background(), `
		SELECT correlation_id FROM audit.org__events WHERE action = 'org.unit.create' AND payload->>'denied' IS NULL
	`).Scan(&correlation)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if correlation == nil || *correlation != "corr-org-1" {
		t.Fatalf("correlation_id = %v, want corr-org-1", correlation)
	}
}
