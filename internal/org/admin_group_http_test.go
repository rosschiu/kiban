// SPDX-License-Identifier: Apache-2.0

// Org-side coverage for the admin group surface (handleAdminGroupList/
// handleAdminCreateGroup/handleAddGroupMember/handleRemoveGroupMember) — same shape as
// admin_position_http_test.go: body-companyId-rejected 422,
// member-count-carrying list rows, and the single-writer invariant surfacing as 409
// GROUP_EXTERNALLY_MANAGED at the HTTP layer. The gateway-level negative matrix (401/403/503/
// forged-header) lives in internal/gateway.
package org

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestHTTP_AdminListGroups_IncludesMemberCount(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store

	company := mustCreateCompany(t, store, "AGH1")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")
	alice := mustCreateMember(t, store, company.ID, "ALICE")
	if _, err := store.AddGroupMember(context.Background(), "test-actor", group.ID, alice.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	rec := doJSON(t, f, "GET", "/internal/org/companies/"+company.ID.String()+"/groups", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	items, ok := data["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 item, got %v", data)
	}
	row := items[0].(map[string]any)
	if row["id"] != group.ID.String() {
		t.Fatalf("id = %v, want %v", row["id"], group.ID.String())
	}
	if row["source"] != "kiban" {
		t.Fatalf("source = %v, want kiban", row["source"])
	}
	if row["isKibanManaged"] != true {
		t.Fatalf("isKibanManaged = %v, want true", row["isKibanManaged"])
	}
	if mc, ok := row["memberCount"].(float64); !ok || mc != 1 {
		t.Fatalf("memberCount = %v, want 1", row["memberCount"])
	}
}

func TestHTTP_AdminCreateGroup_CompanyFromPathOnly(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "AGH2")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/groups", `{"code":"support","name":"Support Team"}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["companyId"] != company.ID.String() {
		t.Fatalf("companyId = %v, want %v", data["companyId"], company.ID.String())
	}
	if data["source"] != "kiban" {
		t.Fatalf("source = %v, want kiban", data["source"])
	}
}

func TestHTTP_AdminCreateGroup_BodyCompanyId_Rejected422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "AGH3")
	other := mustCreateCompany(t, store, "AGH3B")

	rec := doJSON(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/groups",
		`{"code":"support","name":"Support Team","companyId":"`+other.ID.String()+`"}`)
	if rec.Code != 422 {
		t.Fatalf("status = %d, want 422 for a body companyId, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "VALIDATION_ERROR" {
		t.Fatalf("error.code = %v, want VALIDATION_ERROR", errObj["code"])
	}
}

func TestHTTP_AddRemoveGroupMember_RoundTrip(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "AGH4")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")
	member := mustCreateMember(t, store, company.ID, "ALICE")

	addRec := doJSON(t, f, "POST", "/internal/org/groups/"+group.ID.String()+"/members", `{"memberId":"`+member.ID.String()+`"}`)
	if addRec.Code != 201 {
		t.Fatalf("add status = %d, want 201, body=%s", addRec.Code, addRec.Body.String())
	}
	addData := mustEnvelopeData(t, addRec)
	if addData["memberDisplayName"] != member.DisplayName {
		t.Fatalf("memberDisplayName = %v, want %v", addData["memberDisplayName"], member.DisplayName)
	}

	listRec := doJSON(t, f, "GET", "/internal/org/groups/"+group.ID.String()+"/members", "")
	if listRec.Code != 200 {
		t.Fatalf("list status = %d, want 200, body=%s", listRec.Code, listRec.Body.String())
	}

	removeRec := doJSON(t, f, "DELETE", "/internal/org/groups/"+group.ID.String()+"/members/"+member.ID.String(), "")
	if removeRec.Code != 200 {
		t.Fatalf("remove status = %d, want 200, body=%s", removeRec.Code, removeRec.Body.String())
	}
}

// TestHTTP_AddGroupMember_ExternallySourced_409 proves the single-writer invariant surfaces as
// 409 GROUP_EXTERNALLY_MANAGED through the HTTP layer.
func TestHTTP_AddGroupMember_ExternallySourced_409(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	admin := adminPool(t)
	company := mustCreateCompany(t, store, "AGH5")
	member := mustCreateMember(t, store, company.ID, "ALICE")
	externalGroupID := mustCreateExternalGroup(t, admin, company.ID, "AD-ENG", "entra:contoso", "grp-ad-eng-001")

	rec := doJSON(t, f, "POST", "/internal/org/groups/"+externalGroupID.String()+"/members", `{"memberId":"`+member.ID.String()+`"}`)
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "GROUP_EXTERNALLY_MANAGED" {
		t.Fatalf("error.code = %v, want GROUP_EXTERNALLY_MANAGED", errObj["code"])
	}
}

func TestHTTP_RemoveGroupMember_ExternallySourced_409(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	admin := adminPool(t)
	company := mustCreateCompany(t, store, "AGH6")
	member := mustCreateMember(t, store, company.ID, "ALICE")
	externalGroupID := mustCreateExternalGroup(t, admin, company.ID, "AD-SALES", "entra:contoso", "grp-ad-sales-001")

	rec := doJSON(t, f, "DELETE", "/internal/org/groups/"+externalGroupID.String()+"/members/"+member.ID.String(), "")
	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "GROUP_EXTERNALLY_MANAGED" {
		t.Fatalf("error.code = %v, want GROUP_EXTERNALLY_MANAGED", errObj["code"])
	}
}

func TestHTTP_AdminCreateGroup_ActorIsRealBearerSubject(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "AGH7")

	token := unsignedJWTWithSubject(t, "bearer-sub-410")
	rec := doJSONWithAuth(t, f, "POST", "/internal/org/companies/"+company.ID.String()+"/groups",
		`{"code":"support","name":"Support Team"}`, "Bearer "+token)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	admin := adminPool(t)
	var actor string
	if err := admin.QueryRow(context.Background(), `
		SELECT actor FROM audit.org__events WHERE action='org.group.create' ORDER BY id DESC LIMIT 1`,
	).Scan(&actor); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if actor != "bearer-sub-410" {
		t.Fatalf("audit actor = %q, want bearer-sub-410", actor)
	}
}

func TestHTTP_AdminListGroups_InvalidCompanyId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, "GET", "/internal/org/companies/not-a-uuid/groups", "")
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_GetGroup_ReturnsCompanyAndSource proves the S2S read (GET
// /internal/org/groups/{id}) — the shape a module binding a group (e.g. helpdesk) needs for its
// own company-mismatch check, mirroring handleGetPosition's role for the position path.
func TestHTTP_GetGroup_ReturnsCompanyAndSource(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	store := f.svc.store
	company := mustCreateCompany(t, store, "AGH8")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")

	rec := doJSON(t, f, "GET", "/internal/org/groups/"+group.ID.String(), "")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["companyId"] != company.ID.String() {
		t.Fatalf("companyId = %v, want %v", data["companyId"], company.ID.String())
	}
	if data["source"] != "kiban" {
		t.Fatalf("source = %v, want kiban", data["source"])
	}
}

func TestHTTP_GetGroup_NotFound404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, "GET", "/internal/org/groups/"+uuid.New().String(), "")
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}
