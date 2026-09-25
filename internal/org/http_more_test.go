// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/errenv"
)

// allowAllAuthorizer is a local test double that always allows — the shipped v1
// denyAllAuthorizer default (exercised by http_test.go) is never touched by this file. Tests
// using the default only ever reach the fail-closed 503 path since denyAllAuthorizer intercepts
// every mutation before the store is touched, so the vast majority of http.go's handler bodies
// (success paths, validation, not-found, conflict) were entirely unreached without this double.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return true, nil
}

// newAllowAllFixture builds a Service backed by real DB fixtures, an allow-all authorizer, and
// the given identity checker (nil defaults to an empty fakeIdentityChecker — fine for every
// handler except link-user).
func newAllowAllFixture(t *testing.T, identity IdentityStateChecker) *httpTestFixture {
	t.Helper()
	admin := adminPool(t)
	resetOrgFixtures(t, admin)

	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	store := NewStore(orgPool(t), auditWriter)
	if identity == nil {
		identity = &fakeIdentityChecker{exists: map[string]bool{}}
	}
	svc := NewService(store, identity, allowAllAuthorizer{}, auditWriter)
	return &httpTestFixture{svc: svc}
}

// closedPoolFixture builds a Service whose Store's pool is already closed — every query fails
// deterministically at the connection level (no timing race, no hand-edited migration state).
// Used only to reach the generic writeInternalError/auditDenial-Begin-error branches.
func closedPoolFixture(t *testing.T, authz AdminAuthorizer) *httpTestFixture {
	t.Helper()
	pool := orgPool(t)
	pool.Close()
	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	store := NewStore(pool, auditWriter)
	identity := &fakeIdentityChecker{exists: map[string]bool{}}
	svc := NewService(store, identity, authz, auditWriter)
	return &httpTestFixture{svc: svc}
}

func doJSON(t *testing.T, f *httpTestFixture, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	return rec
}

func mustEnvelopeData(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	body := decodeEnvelope(t, rec)
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected a data object, got %v", body)
	}
	return data
}

func mustEnvelopeError(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected an error object, got %v", body)
	}
	return errObj
}

// ---- org units --------------------------------------------------------------------------------

func TestHTTP_CreateUnit_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"cu1","name":"CU One"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["code"] != "CU1" {
		t.Errorf("code = %v, want CU1 (normalized)", data["code"])
	}
}

func TestHTTP_CreateUnit_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateUnit_InvalidParentId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"territory","parentId":"not-a-uuid","code":"cu2","name":"CU Two"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "BAD_REQUEST" {
		t.Errorf("code = %v, want BAD_REQUEST", errObj["code"])
	}
}

func TestHTTP_CreateUnit_ValidationError_422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"x","name":"CU"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", errObj["code"])
	}
}

func TestHTTP_CreateUnit_DuplicateCode_Conflict(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"dupco","name":"Dup Co"}`)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"dupco","name":"Dup Co Two"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["code"] != "CONFLICT" {
		t.Errorf("code = %v, want CONFLICT", errObj["code"])
	}
}

func TestHTTP_GetUnit_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/units/not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetUnit_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/units/"+uuid.New().String(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateUnit_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UU1")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/units/"+company.ID.String(), `{"typeKey":"company","code":"uu1-new","name":"UU One Renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["code"] != "UU1-NEW" {
		t.Errorf("code = %v, want UU1-NEW", data["code"])
	}
}

func TestHTTP_UpdateUnit_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/units/not-a-uuid", `{"code":"x","name":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateUnit_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UU2")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/units/"+company.ID.String(), `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateUnit_InvalidParentId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UU3")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/units/"+company.ID.String(), `{"code":"uu3","name":"UU3","parentId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateUnit_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/units/"+uuid.New().String(), `{"code":"ghost","name":"Ghost"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeleteUnit_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "DU1")
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/units/"+company.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeleteUnit_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/units/not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeleteUnit_HasChildren_422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "DU2")
	mustCreateUnit(t, f.svc.store, "territory", company.ID, "DU2-T")
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/units/"+company.ID.String(), "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	errObj := mustEnvelopeError(t, rec)
	if errObj["details"].(map[string]any)["field"] != "id" {
		t.Errorf("details = %v, want field=id", errObj["details"])
	}
}

func TestHTTP_DeleteUnit_HasMembers_422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "DU3")
	mustCreateMember(t, f.svc.store, company.ID, "DU3-M")
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/units/"+company.ID.String(), "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Subtree_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/units/not-a-uuid/subtree", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

// ---- members ------------------------------------------------------------------------------

func TestHTTP_CreateMember_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CM1")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members", `{"companyId":"`+company.ID.String()+`","code":"cm1","displayName":"CM One","email":"cm1@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["displayName"] != "CM One" {
		t.Errorf("displayName = %v, want CM One", data["displayName"])
	}
}

func TestHTTP_CreateMember_InvalidCompanyId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members", `{"companyId":"not-a-uuid","code":"cm2","displayName":"CM Two"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateMember_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateMember_ValidationError_422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CM3")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members", `{"companyId":"`+company.ID.String()+`","code":"cm3","displayName":""}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetMember_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "GM1")
	member := mustCreateMember(t, f.svc.store, company.ID, "GM1-M")
	rec := doJSON(t, f, http.MethodGet, "/internal/org/members/"+member.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetMember_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/members/"+uuid.New().String(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_ListMembers_InvalidCompanyId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/members?companyId=not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateMember_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UM1")
	member := mustCreateMember(t, f.svc.store, company.ID, "UM1-M")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/members/"+member.ID.String(), `{"displayName":"Updated","email":"upd@example.com","isActive":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["displayName"] != "Updated" || data["isActive"] != false {
		t.Errorf("data = %v, want displayName=Updated isActive=false", data)
	}
}

func TestHTTP_UpdateMember_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/members/not-a-uuid", `{"displayName":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateMember_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UM2")
	member := mustCreateMember(t, f.svc.store, company.ID, "UM2-M")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/members/"+member.ID.String(), `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdateMember_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/members/"+uuid.New().String(), `{"displayName":"Ghost"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_LinkUser_Success(t *testing.T) {
	identity := &fakeIdentityChecker{exists: map[string]bool{"lu-kcsub-1": true}}
	f := newAllowAllFixture(t, identity)
	company := mustCreateCompany(t, f.svc.store, "LU1")
	admin := adminPool(t)
	mustCreateIdentityUser(t, admin, "lu-kcsub-1")
	member := mustCreateMember(t, f.svc.store, company.ID, "LU1-M")

	rec := doJSON(t, f, http.MethodPost, "/internal/org/members/"+member.ID.String()+"/link-user", `{"kcSub":"lu-kcsub-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["userId"] == nil {
		t.Errorf("expected userId to be set after link, got %v", data)
	}
}

func TestHTTP_LinkUser_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members/not-a-uuid/link-user", `{"kcSub":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_LinkUser_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "LU2")
	member := mustCreateMember(t, f.svc.store, company.ID, "LU2-M")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members/"+member.ID.String()+"/link-user", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_LinkUser_NotConfirmed_422(t *testing.T) {
	f := newAllowAllFixture(t, &fakeIdentityChecker{exists: map[string]bool{}})
	company := mustCreateCompany(t, f.svc.store, "LU3")
	member := mustCreateMember(t, f.svc.store, company.ID, "LU3-M")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members/"+member.ID.String()+"/link-user", `{"kcSub":"ghost-kcsub"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UnlinkUser_Success(t *testing.T) {
	identity := &fakeIdentityChecker{exists: map[string]bool{"uu-kcsub-1": true}}
	f := newAllowAllFixture(t, identity)
	company := mustCreateCompany(t, f.svc.store, "UU4")
	admin := adminPool(t)
	mustCreateIdentityUser(t, admin, "uu-kcsub-1")
	member := mustCreateMember(t, f.svc.store, company.ID, "UU4-M")
	if _, err := f.svc.store.LinkUser(context.Background(), "test", identity, member.ID, "uu-kcsub-1"); err != nil {
		t.Fatalf("link user fixture setup: %v", err)
	}

	rec := doJSON(t, f, http.MethodDelete, "/internal/org/members/"+member.ID.String()+"/link-user", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["userId"] != nil {
		t.Errorf("expected userId=nil after unlink, got %v", data["userId"])
	}
}

func TestHTTP_UnlinkUser_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/members/not-a-uuid/link-user", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UnlinkUser_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/members/"+uuid.New().String()+"/link-user", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// ---- positions ----------------------------------------------------------------------------

func TestHTTP_CreatePosition_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CP1")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions",
		`{"companyId":"`+company.ID.String()+`","code":"cp1","title":"CP One","orgUnitId":"`+company.ID.String()+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreatePosition_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreatePosition_InvalidIds_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions", `{"companyId":"not-a-uuid","code":"cp2","title":"CP Two","orgUnitId":"also-not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreatePosition_ValidationError_422(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CP3")
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions",
		`{"companyId":"`+company.ID.String()+`","code":"x","title":"CP Three","orgUnitId":"`+company.ID.String()+`"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetPosition_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "GP1")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "GP1-P")
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions/"+position.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_GetPosition_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions/"+uuid.New().String(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_ListPositions_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "LP1")
	mustCreatePosition(t, f.svc.store, company.ID, company.ID, "LP1-P")
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions?companyId="+company.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["total"].(float64) != 1 {
		t.Errorf("total = %v, want 1", data["total"])
	}
}

func TestHTTP_ListPositions_InvalidCompanyId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions?companyId=not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdatePosition_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UP1")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "UP1-P")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/positions/"+position.ID.String(),
		`{"title":"Updated Title","orgUnitId":"`+company.ID.String()+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	if data["title"] != "Updated Title" {
		t.Errorf("title = %v, want Updated Title", data["title"])
	}
}

func TestHTTP_UpdatePosition_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/positions/not-a-uuid", `{"title":"x","orgUnitId":"`+uuid.New().String()+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdatePosition_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UP2")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "UP2-P")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/positions/"+position.ID.String(), `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdatePosition_InvalidOrgUnitId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "UP3")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "UP3-P")
	rec := doJSON(t, f, http.MethodPut, "/internal/org/positions/"+position.ID.String(), `{"title":"x","orgUnitId":"not-a-uuid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UpdatePosition_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPut, "/internal/org/positions/"+uuid.New().String(), `{"title":"x","orgUnitId":"`+uuid.New().String()+`"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeletePosition_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "DP1")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "DP1-P")
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/positions/"+position.ID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeletePosition_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/positions/not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_DeletePosition_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodDelete, "/internal/org/positions/"+uuid.New().String(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_HolderOnDate_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "HD1")
	member := mustCreateMember(t, f.svc.store, company.ID, "HD1-M")
	position, _, err := f.svc.store.CreateAndAssign(context.Background(), "test-actor", company.ID, "HD1-P", "HD1-P", company.ID, member.ID, date("2026-01-01"), nil)
	if err != nil {
		t.Fatalf("create assignment fixture: %v", err)
	}
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions/"+position.ID.String()+"/holder?date=2026-06-01", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_HolderOnDate_InvalidDate_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "HD2")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "HD2-P")
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions/"+position.ID.String()+"/holder?date=not-a-date", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_HolderOnDate_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "HD3")
	position := mustCreatePosition(t, f.svc.store, company.ID, company.ID, "HD3-P")
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions/"+position.ID.String()+"/holder?date=2020-01-01", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// ---- create-and-assign / end-assignment ----------------------------------------------------

func TestHTTP_CreateAndAssign_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CAA1")
	member := mustCreateMember(t, f.svc.store, company.ID, "CAA1-M")
	body := `{"companyId":"` + company.ID.String() + `","code":"caa1","title":"CAA One","orgUnitId":"` + company.ID.String() +
		`","memberId":"` + member.ID.String() + `","validFrom":"2026-01-01"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateAndAssign_WithValidTo_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CAA2")
	member := mustCreateMember(t, f.svc.store, company.ID, "CAA2-M")
	body := `{"companyId":"` + company.ID.String() + `","code":"caa2","title":"CAA Two","orgUnitId":"` + company.ID.String() +
		`","memberId":"` + member.ID.String() + `","validFrom":"2026-01-01","validTo":"2026-12-31"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	envelope := decodeEnvelope(t, rec)
	data := envelope["data"].(map[string]any)
	assignment := data["assignment"].(map[string]any)
	if assignment["validTo"] != "2026-12-31" {
		t.Errorf("validTo = %v, want 2026-12-31", assignment["validTo"])
	}
}

func TestHTTP_CreateAndAssign_InvalidBody_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateAndAssign_InvalidIds_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	body := `{"companyId":"not-a-uuid","code":"x","title":"x","orgUnitId":"not-a-uuid","memberId":"not-a-uuid","validFrom":"2026-01-01"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateAndAssign_InvalidValidFrom_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CAA3")
	member := mustCreateMember(t, f.svc.store, company.ID, "CAA3-M")
	body := `{"companyId":"` + company.ID.String() + `","code":"caa3","title":"x","orgUnitId":"` + company.ID.String() +
		`","memberId":"` + member.ID.String() + `","validFrom":"not-a-date"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateAndAssign_InvalidValidTo_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CAA4")
	member := mustCreateMember(t, f.svc.store, company.ID, "CAA4-M")
	body := `{"companyId":"` + company.ID.String() + `","code":"caa4","title":"x","orgUnitId":"` + company.ID.String() +
		`","memberId":"` + member.ID.String() + `","validFrom":"2026-01-01","validTo":"not-a-date"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateAndAssign_StoreError_500(t *testing.T) {
	// memberId references a real UUID with no org.member row -> foreign_key_violation classified
	// to a *ValidationError by classifyPgError, NOT a 500 — kept here only to prove the store-error
	// branch is writeStoreError, not a crash; see writeStoreError's own switch for the real mapping.
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "CAA5")
	ghost := mustCreateCompany(t, f.svc.store, "CAA5-GHOST").ID
	body := `{"companyId":"` + company.ID.String() + `","code":"caa5","title":"x","orgUnitId":"` + company.ID.String() +
		`","memberId":"` + ghost.String() + `","validFrom":"2026-01-01"}`
	rec := doJSON(t, f, http.MethodPost, "/internal/org/positions:create-and-assign", body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_EndAssignment_Success proves the end-NOW surface: no request body is
// consulted any more — the server always closes the window as of today, regardless of what (if
// anything) the caller sends as a body.
func TestHTTP_EndAssignment_Success(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "EA1")
	member := mustCreateMember(t, f.svc.store, company.ID, "EA1-M")
	_, assignment, err := f.svc.store.CreateAndAssign(context.Background(), "test-actor", company.ID, "EA1-P", "EA1-P", company.ID, member.ID, mustToday(t, f.svc.store).AddDate(0, 0, -30), nil)
	if err != nil {
		t.Fatalf("create assignment fixture: %v", err)
	}
	rec := doJSON(t, f, http.MethodPost, "/internal/org/assignments/"+assignment.ID.String()+"/end", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := mustEnvelopeData(t, rec)
	want := mustToday(t, f.svc.store).Format("2006-01-02")
	if data["validTo"] != want {
		t.Errorf("validTo = %v, want %s (today)", data["validTo"], want)
	}
}

func TestHTTP_EndAssignment_InvalidId_400(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/assignments/not-a-uuid/end", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_EndAssignment_NotFound_404(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	rec := doJSON(t, f, http.MethodPost, "/internal/org/assignments/"+uuid.New().String()+"/end", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// ---- generic error branches (writeInternalError, auditDenial's Begin-error, ready 500) --------

func TestHTTP_ListMembers_StoreError_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	// handleListMembers is gated by requireMemberOrAdmin, which itself makes a
	// store call (MemberByCompanyAndKcSub) — kcSub is required to reach that call at all (a
	// missing kcSub is 400, proven separately by TestHTTP_ListMembers_UngatedCallerRejected),
	// and the closed pool makes THAT call fail, which is still the 500 this test proves.
	rec := doJSON(t, f, http.MethodGet, "/internal/org/members?companyId="+uuid.New().String()+"&kcSub=x", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_ListPositions_StoreError_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodGet, "/internal/org/positions?companyId="+uuid.New().String(), "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Subtree_StoreError_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodGet, "/internal/org/units/"+uuid.New().String()+"/subtree", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CompanyState_StoreError_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodGet, "/internal/org/companies/"+uuid.New().String()+"/state", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MemberByKcSub_StoreError_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodGet, "/internal/org/companies/"+uuid.New().String()+"/members/by-kcsub/x", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Ready_StoreError_503(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodGet, "/ready", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateUnit_AuthorizedButStoreFails_500 reaches handleCreateUnit's default
// writeStoreError -> writeInternalError branch: an allowed caller whose mutation fails at the
// transport level (closed pool), not from a classifiable Postgres error.
func TestHTTP_CreateUnit_AuthorizedButStoreFails_500(t *testing.T) {
	f := closedPoolFixture(t, allowAllAuthorizer{})
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"cufail","name":"CU Fail"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateUnit_DeniedAuditBeginFails proves auditDenial's own tx.Begin-error early return
// (closed pool) doesn't crash the 503 response path it's attached to.
func TestHTTP_CreateUnit_DeniedAuditBeginFails(t *testing.T) {
	f := closedPoolFixture(t, NewDenyAllAuthorizer())
	rec := doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"cudeny","name":"CU Deny"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}

// TestActorFor covers both of actorFor's branches directly — only the empty-Subject branch is
// currently reachable through the HTTP layer (AuthContext.Subject is never populated by any
// handler — see service.go's own doc comment).
func TestActorFor(t *testing.T) {
	if got := actorFor(AuthContext{}); got != "unauthenticated" {
		t.Errorf("actorFor(empty) = %q, want unauthenticated", got)
	}
	if got := actorFor(AuthContext{Subject: "user:1"}); got != "user:1" {
		t.Errorf("actorFor(Subject=user:1) = %q, want user:1", got)
	}
}

// TestDecodeJSON_Direct covers decodeJSON's own true/false branches directly (also reached
// transitively by every handler test above, but a direct unit call documents the contract).
func TestDecodeJSON_Direct(t *testing.T) {
	rec := httptest.NewRecorder()
	var v map[string]any
	ok := decodeJSON(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":1}`)), &v)
	if !ok {
		t.Error("decodeJSON(valid) = false, want true")
	}

	rec2 := httptest.NewRecorder()
	ok2 := decodeJSON(rec2, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`not json`)), &v)
	if ok2 {
		t.Error("decodeJSON(invalid) = true, want false")
	}
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec2.Code)
	}
}

// TestHTTP_EndAssignment_AlreadyEnded_409 proves the wire shape: a second end on the same
// assignment is 409 ASSIGNMENT_ALREADY_ENDED.
func TestHTTP_EndAssignment_AlreadyEnded_409(t *testing.T) {
	f := newAllowAllFixture(t, nil)
	company := mustCreateCompany(t, f.svc.store, "EA9")
	member := mustCreateMember(t, f.svc.store, company.ID, "EA9-M")
	_, assignment, err := f.svc.store.CreateAndAssign(context.Background(), "test-actor", company.ID, "EA9-P", "EA9-P", company.ID, member.ID, mustToday(t, f.svc.store).AddDate(0, 0, -30), nil)
	if err != nil {
		t.Fatalf("create assignment fixture: %v", err)
	}
	path := "/internal/org/assignments/" + assignment.ID.String() + "/end"
	if rec := doJSON(t, f, http.MethodPost, path, ``); rec.Code != http.StatusOK {
		t.Fatalf("first end: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	rec := doJSON(t, f, http.MethodPost, path, ``)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second end: status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error.Code != errenv.CodeAssignmentAlreadyEnded {
		t.Fatalf("code = %q, want %q", body.Error.Code, errenv.CodeAssignmentAlreadyEnded)
	}
}
