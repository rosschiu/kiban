// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// TestCompanyFacts_Store proves the store-level facts (CompanyState /
// MemberByCompanyAndKcSub) that authz's decision.CompanySource/MembershipSource wire to over
// HTTP — DB-backed, real kiban_org role, same fixture pattern as store_test.go's siblings.
func TestCompanyFacts_Store(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	t.Run("unknown id reports exists=false", func(t *testing.T) {
		exists, isActive, err := store.CompanyState(ctx, uuid.New())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exists || isActive {
			t.Fatalf("exists=%v isActive=%v, want false/false", exists, isActive)
		}
	})

	t.Run("non-company-typed org_unit reports exists=false", func(t *testing.T) {
		company := mustCreateCompany(t, store, "CFSTORE1")
		bu := mustCreateUnit(t, store, "business_unit", company.ID, "CFSTOREBU1")
		exists, _, err := store.CompanyState(ctx, bu.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exists {
			t.Fatalf("exists=true for a non-company-typed unit, want false")
		}
	})

	t.Run("active company reports exists=true isActive=true", func(t *testing.T) {
		company := mustCreateCompany(t, store, "CFSTORE2")
		exists, isActive, err := store.CompanyState(ctx, company.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !exists || !isActive {
			t.Fatalf("exists=%v isActive=%v, want true/true", exists, isActive)
		}
	})

	t.Run("inactive company reports isActive=false", func(t *testing.T) {
		unit, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "CFSTORE3", "Inactive Co", false)
		if err != nil {
			t.Fatalf("create inactive company: %v", err)
		}
		exists, isActive, err := store.CompanyState(ctx, unit.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !exists || isActive {
			t.Fatalf("exists=%v isActive=%v, want true/false", exists, isActive)
		}
	})

	t.Run("unlinked kcSub reports isMember=false", func(t *testing.T) {
		company := mustCreateCompany(t, store, "CFSTORE4")
		mustCreateMember(t, store, company.ID, "CFM1")
		isMember, _, _, err := store.MemberByCompanyAndKcSub(ctx, company.ID, "no-such-kcsub")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isMember {
			t.Fatalf("isMember=true for an unlinked kcSub, want false")
		}
	})

	t.Run("linked active member reports isMember=true isActive=true with the member id", func(t *testing.T) {
		company := mustCreateCompany(t, store, "CFSTORE5")
		member := mustCreateMember(t, store, company.ID, "CFM2")
		mustCreateIdentityUser(t, admin, "cf-kcsub-5")
		linked, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"cf-kcsub-5": true}}, member.ID, "cf-kcsub-5")
		if err != nil {
			t.Fatalf("link user: %v", err)
		}
		isMember, memberID, isActive, err := store.MemberByCompanyAndKcSub(ctx, company.ID, "cf-kcsub-5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isMember || !isActive || memberID != linked.ID {
			t.Fatalf("isMember=%v isActive=%v memberID=%v, want true/true/%v", isMember, isActive, memberID, linked.ID)
		}
	})

	t.Run("linked but deactivated member reports isMember=true isActive=false", func(t *testing.T) {
		company := mustCreateCompany(t, store, "CFSTORE6")
		member := mustCreateMember(t, store, company.ID, "CFM3")
		mustCreateIdentityUser(t, admin, "cf-kcsub-6")
		linked, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"cf-kcsub-6": true}}, member.ID, "cf-kcsub-6")
		if err != nil {
			t.Fatalf("link user: %v", err)
		}
		if _, err := store.UpdateMember(ctx, "test-actor", linked.ID, linked.DisplayName, linked.Email, false); err != nil {
			t.Fatalf("deactivate member: %v", err)
		}
		isMember, _, isActive, err := store.MemberByCompanyAndKcSub(ctx, company.ID, "cf-kcsub-6")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isMember || isActive {
			t.Fatalf("isMember=%v isActive=%v, want true/false", isMember, isActive)
		}
	})

	t.Run("same kcSub linked in a different company reports isMember=false", func(t *testing.T) {
		companyA := mustCreateCompany(t, store, "CFSTORE7A")
		companyB := mustCreateCompany(t, store, "CFSTORE7B")
		memberA := mustCreateMember(t, store, companyA.ID, "CFM7")
		mustCreateIdentityUser(t, admin, "cf-kcsub-7")
		if _, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"cf-kcsub-7": true}}, memberA.ID, "cf-kcsub-7"); err != nil {
			t.Fatalf("link user: %v", err)
		}
		isMember, _, _, err := store.MemberByCompanyAndKcSub(ctx, companyB.ID, "cf-kcsub-7")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isMember {
			t.Fatalf("isMember=true for a member linked in a DIFFERENT company, want false")
		}
	})
}

// TestCompanyFacts_HTTP proves the two internal endpoints end-to-end over the real HTTP mux
// (open reads, no AdminAuthorizer gate — same as GET /internal/org/units/{id}).
func TestCompanyFacts_HTTP(t *testing.T) {
	f := newHTTPTestFixture(t)
	admin := adminPool(t)

	company := mustCreateCompany(t, f.svc.store, "CFHTTP1")
	member := mustCreateMember(t, f.svc.store, company.ID, "CFHM1")
	mustCreateIdentityUser(t, admin, "cf-http-kcsub")
	if _, err := f.svc.store.LinkUser(context.Background(), "test-actor",
		&fakeIdentityChecker{exists: map[string]bool{"cf-http-kcsub": true}}, member.ID, "cf-http-kcsub"); err != nil {
		t.Fatalf("link user: %v", err)
	}

	t.Run("state: existing active company", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/state", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		data := body["data"].(map[string]any)
		if data["exists"] != true || data["isActive"] != true {
			t.Fatalf("data = %+v, want exists/isActive true", data)
		}
	})

	t.Run("state: unknown id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+uuid.New().String()+"/state", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		data := body["data"].(map[string]any)
		if data["exists"] != false {
			t.Fatalf("data = %+v, want exists=false", data)
		}
	})

	t.Run("members/by-kcsub: linked member", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members/by-kcsub/cf-http-kcsub", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		data := body["data"].(map[string]any)
		if data["isMember"] != true || data["isActive"] != true || data["memberId"] != member.ID.String() {
			t.Fatalf("data = %+v, want isMember/isActive true and memberId %s", data, member.ID.String())
		}
	})

	t.Run("members/by-kcsub: unlinked kcSub", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members/by-kcsub/never-seen", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		data := body["data"].(map[string]any)
		if data["isMember"] != false || data["memberId"] != nil {
			t.Fatalf("data = %+v, want isMember=false memberId=nil", data)
		}
	})

	t.Run("state: invalid id is 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/not-a-uuid/state", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})
}
