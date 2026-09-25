// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
)

// --- The browser-reachable, authorized company member directory. ---

// TestStore_MemberDirectory_ActiveOnlyReducedView proves the store method returns only ACTIVE
// members, in the REDUCED shape (no code/kcSub/lifecycle), with an inactive member excluded.
func TestStore_MemberDirectory_ActiveOnlyReducedView(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "MDIRCO1")
	active := mustCreateMember(t, f.svc.store, company.ID, "MDA1")
	inactive, err := f.svc.store.CreateMember(context.Background(), "test-actor", company.ID, "MDA2", "Inactive Member", "", false)
	if err != nil {
		t.Fatalf("create inactive member: %v", err)
	}

	entries, total, err := f.svc.store.MemberDirectory(context.Background(), company.ID, "", 1, 25)
	if err != nil {
		t.Fatalf("MemberDirectory: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1 (inactive member must be excluded)", total)
	}
	if len(entries) != 1 || entries[0].ID != active.ID {
		t.Fatalf("entries = %+v, want exactly the active member %s", entries, active.ID)
	}
	if entries[0].HasLinkedUser {
		t.Fatalf("HasLinkedUser = true, want false (no user linked)")
	}
	_ = inactive
}

// TestStore_MemberDirectory_QFilter proves the optional substring filter matches displayName OR
// email, case-insensitively, and excludes non-matches.
func TestStore_MemberDirectory_QFilter(t *testing.T) {
	f := newHTTPTestFixture(t)
	company := mustCreateCompany(t, f.svc.store, "MDIRCO2")
	alice, err := f.svc.store.CreateMember(context.Background(), "test-actor", company.ID, "MDA3", "Alice Anderson", "alice@example.com", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	_, err = f.svc.store.CreateMember(context.Background(), "test-actor", company.ID, "MDA4", "Bob Brown", "bob@example.com", true)
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	t.Run("matches displayName, case-insensitive", func(t *testing.T) {
		entries, total, err := f.svc.store.MemberDirectory(context.Background(), company.ID, "aLiCe", 1, 25)
		if err != nil {
			t.Fatalf("MemberDirectory: %v", err)
		}
		if total != 1 || entries[0].ID != alice.ID {
			t.Fatalf("entries = %+v total=%d, want exactly alice", entries, total)
		}
	})

	t.Run("matches email", func(t *testing.T) {
		entries, total, err := f.svc.store.MemberDirectory(context.Background(), company.ID, "bob@example", 1, 25)
		if err != nil {
			t.Fatalf("MemberDirectory: %v", err)
		}
		if total != 1 || entries[0].DisplayName != "Bob Brown" {
			t.Fatalf("entries = %+v total=%d, want exactly bob", entries, total)
		}
	})

	t.Run("no match: empty, not an error", func(t *testing.T) {
		entries, total, err := f.svc.store.MemberDirectory(context.Background(), company.ID, "nonexistent-zzz", 1, 25)
		if err != nil {
			t.Fatalf("MemberDirectory: %v", err)
		}
		if total != 0 || len(entries) != 0 {
			t.Fatalf("entries = %+v total=%d, want none", entries, total)
		}
	})
}

// httpMemberDirectoryFixture wires a Service with a real, live, engine-backed AdminAuthorizer
// (unlike newHTTPTestFixture's NewDenyAllAuthorizer) so tests below can exercise BOTH gate paths
// of requireMemberOrAdmin: real membership, and the superadmin fallback.
type httpMemberDirectoryFixture struct {
	svc      *Service
	authzSrv *httptest.Server
	allow    bool // toggled per sub-test to control the fake authz server's answer
}

func newHTTPMemberDirectoryFixture(t *testing.T) *httpMemberDirectoryFixture {
	t.Helper()
	admin := adminPool(t)
	resetOrgFixtures(t, admin)

	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	store := NewStore(orgPool(t), auditWriter)
	identity := &fakeIdentityChecker{exists: map[string]bool{}}

	f := &httpMemberDirectoryFixture{}
	f.authzSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f.allow {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": "PLATFORM_ROLE_REQUIRED"}})
	}))
	t.Cleanup(f.authzSrv.Close)

	authz := NewEngineAdminAuthorizer(f.authzSrv.URL, f.authzSrv.Client())
	f.svc = NewService(store, identity, authz, auditWriter)
	return f
}

// TestHandleMemberDirectory_RequiresKcSub proves the 400 "must name yourself" gate.
func TestHandleMemberDirectory_RequiresKcSub(t *testing.T) {
	f := newHTTPMemberDirectoryFixture(t)
	company := mustCreateCompany(t, f.svc.store, "MDIRCO3")

	req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleMemberDirectory_NonMemberNonAdmin_403 proves the fail-closed deny: a kcSub that is
// neither an active member nor (per the fake authz server) a superadmin gets 403, never a
// guessed allow.
func TestHandleMemberDirectory_NonMemberNonAdmin_403(t *testing.T) {
	f := newHTTPMemberDirectoryFixture(t)
	f.allow = false
	company := mustCreateCompany(t, f.svc.store, "MDIRCO4")

	req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members?kcSub=stranger", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleMemberDirectory_ActiveMember_200ReducedView proves the ACTIVE-membership success
// path returns the REDUCED view (id/displayName/email/hasLinkedUser only — no code, no kcSub, no
// lifecycle) — least disclosure.
func TestHandleMemberDirectory_ActiveMember_200ReducedView(t *testing.T) {
	f := newHTTPMemberDirectoryFixture(t)
	f.allow = false // membership alone must be sufficient — prove admin path is NOT what allows this
	admin := adminPool(t)
	company := mustCreateCompany(t, f.svc.store, "MDIRCO5")
	member := mustCreateMember(t, f.svc.store, company.ID, "MDA5")
	mustCreateIdentityUser(t, admin, "mdir-active-member")
	checker := &fakeIdentityChecker{exists: map[string]bool{"mdir-active-member": true}}
	if _, err := f.svc.store.LinkUser(context.Background(), "test-actor", checker, member.ID, "mdir-active-member"); err != nil {
		t.Fatalf("link user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members?kcSub=mdir-active-member", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Total != 1 || len(body.Data.Items) != 1 {
		t.Fatalf("unexpected result: %+v", body.Data)
	}
	item := body.Data.Items[0]
	for _, forbidden := range []string{"kcSub", "code", "lifecycle", "isActive", "userId"} {
		if _, present := item[forbidden]; present {
			t.Errorf("reduced view leaked field %q: %v", forbidden, item)
		}
	}
	for _, required := range []string{"id", "displayName", "email", "hasLinkedUser"} {
		if _, present := item[required]; !present {
			t.Errorf("reduced view missing required field %q: %v", required, item)
		}
	}
}

// TestHandleMemberDirectory_SuperadminFallback_200 proves the OTHER gate leg: a caller who is
// NOT a member but IS the superadmin (per the fake authz server) is still allowed through.
func TestHandleMemberDirectory_SuperadminFallback_200(t *testing.T) {
	f := newHTTPMemberDirectoryFixture(t)
	f.allow = true
	company := mustCreateCompany(t, f.svc.store, "MDIRCO6")
	mustCreateMember(t, f.svc.store, company.ID, "MDA6")

	req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members?kcSub=superadmin-not-a-member", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (superadmin fallback), body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleMemberDirectory_QParam_Forwarded proves the q= query param reaches the store filter
// through the HTTP layer.
func TestHandleMemberDirectory_QParam_Forwarded(t *testing.T) {
	f := newHTTPMemberDirectoryFixture(t)
	f.allow = true // simplest allowed path for this test's focus (the q filter, not the gate)
	company := mustCreateCompany(t, f.svc.store, "MDIRCO7")
	if _, err := f.svc.store.CreateMember(context.Background(), "test-actor", company.ID, "MDA7", "Findme Person", "", true); err != nil {
		t.Fatalf("create member: %v", err)
	}
	if _, err := f.svc.store.CreateMember(context.Background(), "test-actor", company.ID, "MDA8", "Someone Else", "", true); err != nil {
		t.Fatalf("create member: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/org/companies/"+company.ID.String()+"/members?kcSub=x&q=Findme", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Total != 1 || body.Data.Items[0]["displayName"] != "Findme Person" {
		t.Fatalf("q filter not applied through HTTP layer: %+v", body.Data)
	}
}
