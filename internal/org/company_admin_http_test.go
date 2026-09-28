// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// companyScopedAuthorizer stands in for authz: a company administrator of exactly one company.
// Global (superadmin) checks are confirmed denials; company checks pass only for that company.
type companyScopedAuthorizer struct{ company uuid.UUID }

func (a companyScopedAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, &DeniedError{Reason: "PLATFORM_ROLE_REQUIRED"}
}

func (a companyScopedAuthorizer) CanInCompany(ctx context.Context, authCtx AuthContext, action, companyID string) (bool, error) {
	if companyID == a.company.String() {
		return true, nil
	}
	return false, &DeniedError{Reason: "COMPANY_ROLE_REQUIRED"}
}

// TestHTTP_CompanyAdministrator: every company-scoped write resolves the resource's company and
// asks authz about THAT company, so an administrator of one company can manage its members,
// positions, assignments and groups, and nothing in another company; companies and org units
// themselves stay superadmin work.
func TestHTTP_CompanyAdministrator(t *testing.T) {
	f := newHTTPTestFixture(t)
	mine := mustCreateCompany(t, f.svc.store, "CADM1")
	other := mustCreateCompany(t, f.svc.store, "CADM2")
	f.svc.authz = companyScopedAuthorizer{company: mine.ID}

	// Members: create in mine (201), in other (403 COMPANY_ROLE_REQUIRED).
	rec := doJSON(t, f, http.MethodPost, "/internal/org/members", `{"companyId":"`+mine.ID.String()+`","code":"CA1","displayName":"Mine"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create member in own company: %d %s", rec.Code, rec.Body.String())
	}
	memberID := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	rec = doJSON(t, f, http.MethodPost, "/internal/org/members", `{"companyId":"`+other.ID.String()+`","code":"CA2","displayName":"Other"}`)
	if rec.Code != http.StatusForbidden || decodeEnvelope(t, rec)["error"].(map[string]any)["details"].(map[string]any)["reason"] != "COMPANY_ROLE_REQUIRED" {
		t.Fatalf("create member in another company: %d %s, want 403 COMPANY_ROLE_REQUIRED", rec.Code, rec.Body.String())
	}
	// Update/link/unlink resolve the member's company; an unknown member is 404, not a leak of
	// the authorizer's answer.
	if rec = doJSON(t, f, http.MethodPut, "/internal/org/members/"+memberID, `{"displayName":"Mine 2"}`); rec.Code != http.StatusOK {
		t.Fatalf("update own member: %d %s", rec.Code, rec.Body.String())
	}
	otherMember := mustCreateMember(t, f.svc.store, other.ID, "CA3")
	if rec = doJSON(t, f, http.MethodPut, "/internal/org/members/"+otherMember.ID.String(), `{"displayName":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("update another company's member: %d, want 403", rec.Code)
	}
	if rec = doJSON(t, f, http.MethodDelete, "/internal/org/members/"+otherMember.ID.String()+"/link-user", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("unlink another company's member: %d, want 403", rec.Code)
	}
	if rec = doJSON(t, f, http.MethodPut, "/internal/org/members/"+uuid.NewString(), `{"displayName":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("update unknown member: %d, want 404", rec.Code)
	}

	// Positions and assignments: create in mine, assign own member, end it; refused in other.
	rec = doJSON(t, f, http.MethodPost, "/internal/org/companies/"+mine.ID.String()+"/positions", `{"code":"CFO","title":"CFO"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create position: %d %s", rec.Code, rec.Body.String())
	}
	positionID := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/companies/"+other.ID.String()+"/positions", `{"code":"CFO","title":"CFO"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("create position in another company: %d, want 403", rec.Code)
	}
	rec = doJSON(t, f, http.MethodPost, "/internal/org/positions/"+positionID+"/assignments", `{"memberId":"`+memberID+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("assign: %d %s", rec.Code, rec.Body.String())
	}
	assignmentID := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	rec = doJSON(t, f, http.MethodGet, "/internal/org/assignments/"+assignmentID, "")
	if rec.Code != http.StatusOK || decodeEnvelope(t, rec)["data"].(map[string]any)["companyId"] != mine.ID.String() {
		t.Fatalf("get assignment: %d %s, want companyId of own company", rec.Code, rec.Body.String())
	}
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/assignments/"+assignmentID+"/end", ""); rec.Code != http.StatusOK {
		t.Fatalf("end assignment: %d %s", rec.Code, rec.Body.String())
	}
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/assignments/"+uuid.NewString()+"/end", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("end unknown assignment: %d, want 404", rec.Code)
	}

	// Groups: create in mine, add own member; refused on another company's group.
	rec = doJSON(t, f, http.MethodPost, "/internal/org/companies/"+mine.ID.String()+"/groups", `{"code":"SUPPORT","name":"Support"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", rec.Code, rec.Body.String())
	}
	groupID := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/groups/"+groupID+"/members", `{"memberId":"`+memberID+`"}`); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("add group member: %d %s", rec.Code, rec.Body.String())
	}
	f.svc.authz = allowAllAuthorizer{}
	rec = doJSON(t, f, http.MethodPost, "/internal/org/companies/"+other.ID.String()+"/groups", `{"code":"OPS","name":"Ops"}`)
	otherGroupID := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	f.svc.authz = companyScopedAuthorizer{company: mine.ID}
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/groups/"+otherGroupID+"/members", `{"memberId":"`+otherMember.ID.String()+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("add member to another company's group: %d, want 403", rec.Code)
	}

	// Companies and org units stay superadmin work.
	if rec = doJSON(t, f, http.MethodPost, "/internal/org/units", `{"typeKey":"company","code":"CADM3","name":"New"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("create company as a company administrator: %d, want 403", rec.Code)
	}
}
