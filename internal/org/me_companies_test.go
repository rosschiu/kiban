// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMeCompanies_Store proves the store-level read (ListActiveCompaniesForKcSub) —
// DB-backed, real kiban_org role, same fixture pattern as company_facts_test.go's siblings.
func TestMeCompanies_Store(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	t.Run("unknown kcSub returns an empty slice, never an error", func(t *testing.T) {
		got, err := store.ListActiveCompaniesForKcSub(ctx, "no-such-kcsub")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d companies, want 0", len(got))
		}
	})

	t.Run("active membership in an active company is returned", func(t *testing.T) {
		company := mustCreateCompany(t, store, "MCSTORE1")
		member := mustCreateMember(t, store, company.ID, "MCM1")
		mustCreateIdentityUser(t, admin, "mc-kcsub-1")
		if _, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"mc-kcsub-1": true}}, member.ID, "mc-kcsub-1"); err != nil {
			t.Fatalf("link user: %v", err)
		}
		got, err := store.ListActiveCompaniesForKcSub(ctx, "mc-kcsub-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != company.ID || got[0].Code != "MCSTORE1" || !got[0].IsActive {
			t.Fatalf("got %+v, want exactly company %s", got, company.ID)
		}
	})

	t.Run("membership in an inactive company is excluded", func(t *testing.T) {
		unit, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "MCSTORE2", "Inactive Co", false)
		if err != nil {
			t.Fatalf("create inactive company: %v", err)
		}
		member := mustCreateMember(t, store, unit.ID, "MCM2")
		mustCreateIdentityUser(t, admin, "mc-kcsub-2")
		if _, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"mc-kcsub-2": true}}, member.ID, "mc-kcsub-2"); err != nil {
			t.Fatalf("link user: %v", err)
		}
		got, err := store.ListActiveCompaniesForKcSub(ctx, "mc-kcsub-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %+v, want none (company is inactive)", got)
		}
	})

	t.Run("deactivated membership in an active company is excluded", func(t *testing.T) {
		company := mustCreateCompany(t, store, "MCSTORE3")
		member := mustCreateMember(t, store, company.ID, "MCM3")
		mustCreateIdentityUser(t, admin, "mc-kcsub-3")
		linked, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"mc-kcsub-3": true}}, member.ID, "mc-kcsub-3")
		if err != nil {
			t.Fatalf("link user: %v", err)
		}
		if _, err := store.UpdateMember(ctx, "test-actor", linked.ID, linked.DisplayName, linked.Email, false); err != nil {
			t.Fatalf("deactivate member: %v", err)
		}
		got, err := store.ListActiveCompaniesForKcSub(ctx, "mc-kcsub-3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %+v, want none (membership is inactive)", got)
		}
	})

	t.Run("multiple active memberships are returned sorted by company code", func(t *testing.T) {
		companyB := mustCreateCompany(t, store, "MCSTORE4B")
		companyA := mustCreateCompany(t, store, "MCSTORE4A")
		mustCreateIdentityUser(t, admin, "mc-kcsub-4")
		memberA := mustCreateMember(t, store, companyA.ID, "MCM4A")
		memberB := mustCreateMember(t, store, companyB.ID, "MCM4B")
		if _, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"mc-kcsub-4": true}}, memberA.ID, "mc-kcsub-4"); err != nil {
			t.Fatalf("link user A: %v", err)
		}
		if _, err := store.LinkUser(ctx, "test-actor", &fakeIdentityChecker{exists: map[string]bool{"mc-kcsub-4": true}}, memberB.ID, "mc-kcsub-4"); err != nil {
			// A single kcSub can only link one member per company (company-scoped uniqueness),
			// but nothing stops it linking one member in EACH of two different companies.
			t.Fatalf("link user B: %v", err)
		}
		got, err := store.ListActiveCompaniesForKcSub(ctx, "mc-kcsub-4")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0].Code != "MCSTORE4A" || got[1].Code != "MCSTORE4B" {
			t.Fatalf("got %+v, want [MCSTORE4A, MCSTORE4B] in that order", got)
		}
	})
}

// TestMeCompanies_HTTP proves GET /internal/org/me/companies end-to-end over the real HTTP mux
// (open read, no AdminAuthorizer gate — same as the company-facts endpoints).
func TestMeCompanies_HTTP(t *testing.T) {
	f := newHTTPTestFixture(t)
	admin := adminPool(t)

	company := mustCreateCompany(t, f.svc.store, "MCHTTP1")
	member := mustCreateMember(t, f.svc.store, company.ID, "MCHM1")
	mustCreateIdentityUser(t, admin, "mc-http-kcsub")
	if _, err := f.svc.store.LinkUser(context.Background(), "test-actor",
		&fakeIdentityChecker{exists: map[string]bool{"mc-http-kcsub": true}}, member.ID, "mc-http-kcsub"); err != nil {
		t.Fatalf("link user: %v", err)
	}

	t.Run("linked active member's company is returned", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/me/companies?kcSub=mc-http-kcsub", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		items, ok := body["data"].([]any)
		if !ok || len(items) != 1 {
			t.Fatalf("data = %+v, want exactly 1 company", body["data"])
		}
		item := items[0].(map[string]any)
		if item["id"] != company.ID.String() || item["code"] != "MCHTTP1" || item["isActive"] != true {
			t.Fatalf("item = %+v, want company %s", item, company.ID)
		}
	})

	t.Run("unknown kcSub returns an empty list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/me/companies?kcSub=never-seen", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		body := decodeEnvelope(t, rec)
		items, ok := body["data"].([]any)
		if !ok || len(items) != 0 {
			t.Fatalf("data = %+v, want an empty list", body["data"])
		}
	})

	t.Run("missing kcSub is 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/org/me/companies", nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})
}
