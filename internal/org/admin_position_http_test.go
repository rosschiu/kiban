// SPDX-License-Identifier: Apache-2.0

// Org-side coverage for the admin position surface (handleAdminPositionList /
// handleAdminCreatePosition / handleAdminUpdatePosition) — list-with-holder shape, body
// companyId 422 (never trusted), orgUnitId accepted under the company and refused elsewhere,
// org-unit defaults to the company root, retitle and move, and audit actor = the real bearer subject (reusing
// position_holder_test.go's unsignedJWTWithSubject/doJSONWithAuth helpers, same pattern
// TestPositionHolder_Actor_RealBearerSubject already established). The gateway-level negative
// matrix (401/403/503/forged-header) lives in internal/gateway/admin_position_routes_test.go —
// this file proves org's OWN handler-level validation, which the gateway never reimplements.
package org

import (
	"context"
	"testing"

	"github.com/google/uuid"
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

func TestHTTP_AdminCreatePosition_OrgUnitUnderCompany_Accepted(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM5")
	unit := mustCreateUnit(t, store, "business_unit", company.ID, "ADM5-BU")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions",
		`{"code":"cfo","title":"CFO","orgUnitId":"`+unit.ID.String()+`"}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["orgUnitId"] != unit.ID.String() || data["companyId"] != company.ID.String() {
		t.Fatalf("position = %v, want orgUnitId %s under company %s", data, unit.ID, company.ID)
	}
}

func TestHTTP_AdminCreatePosition_OrgUnitOfOtherCompany_Rejected422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM6")
	other := mustCreateCompany(t, store, "ADM6B")
	foreign := mustCreateUnit(t, store, "business_unit", other.ID, "ADM6B-BU")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/positions",
		`{"code":"cfo","title":"CFO","orgUnitId":"`+foreign.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 for another company's unit, body=%s", rec.Code, rec.Body.String())
	}
	if errObj := mustEnvelopeError(t, rec); errObj["code"] != "VALIDATION_ERROR" {
		t.Fatalf("error.code = %v, want VALIDATION_ERROR", errObj["code"])
	}
}

func TestHTTP_AdminUpdatePosition_RetitleAndMove(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM7")
	unit := mustCreateUnit(t, store, "business_unit", company.ID, "ADM7-BU")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")

	rec := doJSON(t, f, "PUT", "/internal/org/admin/positions/"+position.ID.String(), `{"title":"CFO (interim)"}`)
	if rec.Code != 200 {
		t.Fatalf("retitle: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["title"] != "CFO (interim)" || data["orgUnitId"] != company.ID.String() {
		t.Fatalf("after retitle = %v, want new title and unchanged org unit", data)
	}
	rec = doJSON(t, f, "PUT", "/internal/org/admin/positions/"+position.ID.String(), `{"orgUnitId":"`+unit.ID.String()+`"}`)
	if rec.Code != 200 {
		t.Fatalf("move: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data = mustEnvelopeData(t, rec)
	if data["orgUnitId"] != unit.ID.String() || data["title"] != "CFO (interim)" {
		t.Fatalf("after move = %v, want new org unit and unchanged title", data)
	}
}

func TestHTTP_AdminUpdatePosition_OtherCompanyUnit_Rejected422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM8")
	other := mustCreateCompany(t, store, "ADM8B")
	foreign := mustCreateUnit(t, store, "business_unit", other.ID, "ADM8B-BU")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")

	rec := doJSON(t, f, "PUT", "/internal/org/admin/positions/"+position.ID.String(), `{"orgUnitId":"`+foreign.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 for another company's unit, body=%s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, f, "PUT", "/internal/org/admin/positions/"+uuid.New().String(), `{"title":"x"}`); rec.Code != 404 {
		t.Fatalf("unknown position: status = %d, want 404", rec.Code)
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

// TestHTTP_AssignNow_HeldAnswers409PositionHeld: the route answers 409 POSITION_HELD with the
// current assignmentId and memberId in details, never a bare CONFLICT.
func TestHTTP_AssignNow_HeldAnswers409PositionHeld(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "HLD2")
	first := mustCreateMember(t, store, company.ID, "M811")
	second := mustCreateMember(t, store, company.ID, "M812")
	position := mustCreatePosition(t, store, company.ID, company.ID, "COO")
	current, err := store.AssignNow(context.Background(), "actor", position.ID, first.ID)
	if err != nil {
		t.Fatalf("first assign: %v", err)
	}

	rec := doJSON(t, f, "POST", "/internal/org/positions/"+position.ID.String()+"/assignments", `{"memberId":"`+second.ID.String()+`"}`)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
	if errObj["code"] != "POSITION_HELD" {
		t.Fatalf("code = %v, want POSITION_HELD", errObj["code"])
	}
	details := errObj["details"].(map[string]any)
	if details["assignmentId"] != current.ID.String() || details["memberId"] != first.ID.String() {
		t.Fatalf("details = %v, want assignment %s member %s", details, current.ID, first.ID)
	}
}

func TestHTTP_Handover_EndsAndAssigns(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "ADM9")
	dave := mustCreateMember(t, store, company.ID, "DAVE9")
	erin := mustCreateMember(t, store, company.ID, "ERIN9")
	position := mustCreatePosition(t, store, company.ID, company.ID, "CFO")

	rec := doJSON(t, f, "POST", "/internal/org/positions/"+position.ID.String()+"/handover", `{"memberId":"`+dave.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("empty position: status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	first, err := store.AssignNow(context.Background(), "actor", position.ID, dave.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec = doJSON(t, f, "POST", "/internal/org/positions/"+position.ID.String()+"/handover", `{"memberId":"`+erin.ID.String()+`","expectedAssignmentId":"`+erin.ID.String()+`"}`)
	if rec.Code != 409 {
		t.Fatalf("stale expectation: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, f, "POST", "/internal/org/positions/"+position.ID.String()+"/handover", `{"memberId":"`+erin.ID.String()+`","expectedAssignmentId":"`+first.ID.String()+`"}`)
	if rec.Code != 200 {
		t.Fatalf("handover: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	ended, _ := data["ended"].(map[string]any)
	assignment, _ := data["assignment"].(map[string]any)
	if ended["id"] != first.ID.String() || assignment["memberId"] != erin.ID.String() {
		t.Fatalf("handover body = %v", data)
	}
	rec = doJSON(t, f, "POST", "/internal/org/positions/"+position.ID.String()+"/handover", `{"memberId":"`+erin.ID.String()+`"}`)
	if rec.Code != 200 || mustEnvelopeData(t, rec)["ended"] != nil {
		t.Fatalf("repeat: status = %d body=%s, want 200 with ended null", rec.Code, rec.Body.String())
	}
}
