// SPDX-License-Identifier: Apache-2.0

// Org-side coverage for the admin position surface (handleAdminPositionList /
// handleAdminCreatePosition) — list-with-holder shape, body-ID-mismatch 422 (any body
// companyId/orgUnitId is rejected, not trusted), org-unit
// defaults to the company root, and audit actor = the real bearer subject (reusing
// position_holder_test.go's unsignedJWTWithSubject/doJSONWithAuth helpers, same pattern
// TestPositionHolder_Actor_RealBearerSubject already established). The gateway-level negative
// matrix (401/403/503/forged-header) lives in internal/gateway/admin_position_routes_test.go —
// this file proves org's OWN handler-level validation, which the gateway never reimplements.
package org

import (
	"context"
	"testing"
)

func TestHTTP_AdminListPositions_IncludesCurrentHolder(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store

	company := mustCreateCompany(t, store, "ADM1")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")
	member := mustCreateMember(t, store, company.ID, "ALICE")

	assignment, err := store.AssignNow(context.Background(), "test-actor", position.ID, member.ID)
	if err != nil {
		t.Fatalf("assign now: %v", err)
	}

	rec := doJSON(t, f, "GET", "/internal/org/companies/"+company.ID.String()+"/positions", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected a page envelope, got %v", body)
	}
	items, ok := data["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 item, got %v", data)
	}
	row := items[0].(map[string]any)
	if row["id"] != position.ID.String() {
		t.Fatalf("id = %v, want %v", row["id"], position.ID.String())
	}
	if row["assignmentId"] != assignment.ID.String() {
		t.Fatalf("assignmentId = %v, want %v", row["assignmentId"], assignment.ID.String())
	}
	if row["memberId"] != member.ID.String() {
		t.Fatalf("memberId = %v, want %v", row["memberId"], member.ID.String())
	}
	if row["holderDisplayName"] != member.DisplayName {
		t.Fatalf("holderDisplayName = %v, want %v", row["holderDisplayName"], member.DisplayName)
	}
}

func TestHTTP_AdminListPositions_UnassignedRowHasNullHolder(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM2")
	mustCreatePosition(t, store, company.ID, company.ID, "VACANT")

	rec := doJSON(t, f, "GET", "/internal/org/companies/"+company.ID.String()+"/positions", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	items := data["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	row := items[0].(map[string]any)
	if row["assignmentId"] != nil || row["memberId"] != nil || row["holderDisplayName"] != nil {
		t.Fatalf("expected null holder fields for an unassigned position, got %v", row)
	}
}

func TestHTTP_AdminCreatePosition_CompanyFromPathOnly_DefaultsOrgUnitToRoot(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM3")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions", `{"code":"cfo","title":"CFO"}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["companyId"] != company.ID.String() {
		t.Fatalf("companyId = %v, want %v", data["companyId"], company.ID.String())
	}
	if data["orgUnitId"] != company.ID.String() {
		t.Fatalf("orgUnitId = %v, want the company root %v", data["orgUnitId"], company.ID.String())
	}
}

func TestHTTP_AdminCreatePosition_BodyCompanyId_Rejected422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM4")
	other := mustCreateCompany(t, store, "ADM4B")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions",
		`{"code":"cfo","title":"CFO","companyId":"`+other.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 for a body companyId, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "VALIDATION_ERROR" {
		t.Fatalf("error.code = %v, want VALIDATION_ERROR", errObj["code"])
	}
}

func TestHTTP_AdminCreatePosition_BodyOrgUnitId_Rejected422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM5")
	unit := mustCreateUnit(t, store, "business_unit", company.ID, "ADM5-DEPT")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions",
		`{"code":"cfo","title":"CFO","orgUnitId":"`+unit.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 for a body orgUnitId, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_AdminCreatePosition_ActorIsRealBearerSubject(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM6")

	token := unsignedJWTWithSubject(t, "bearer-sub-408")
	rec := doJSONWithAuth(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions",
		`{"code":"cfo","title":"CFO"}`, "Bearer "+token)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	admin := adminPool(t)
	var actor string
	if err := admin.QueryRow(context.Background(), `
		SELECT actor FROM audit.org__events WHERE action='org.position.create' ORDER BY id DESC LIMIT 1`,
	).Scan(&actor); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if actor != "bearer-sub-408" {
		t.Fatalf("audit actor = %q, want bearer-sub-408", actor)
	}
}

func TestHTTP_AdminListPositions_InvalidCompanyId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, "GET", "/internal/org/companies/not-a-uuid/positions", "")
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}
