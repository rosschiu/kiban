// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// companyAdminAuthz is a fake authz that is nobody's superadmin and the administrator of
// exactly one company; it records every decision request.
func companyAdminAuthz(t *testing.T, company string) (*AuthzAdminClient, *[]map[string]any) {
	t.Helper()
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen = append(seen, req)
		w.Header().Set("Content-Type", "application/json")
		if req["scope"] == "company" && req["companyId"] == company && req["requiredCompanyRole"] == "admin" && req["allowPlatformOperatorCompanyScope"] == true {
			_, _ = w.Write([]byte(`{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`))
			return
		}
		reason := "PLATFORM_ROLE_REQUIRED"
		if req["scope"] == "company" {
			reason = "COMPANY_ROLE_REQUIRED"
		}
		_, _ = w.Write([]byte(`{"data":{"allowed":false,"reason":"` + reason + `","evidence":[]}}`))
	}))
	t.Cleanup(srv.Close)
	return NewAuthzAdminClient(srv.URL), &seen
}

func newCompanyAdminFixture(t *testing.T, adminClient *AuthzAdminClient) *foundationTestFixture {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountAdminOrgRoutes(mux, verifier, nil, target, adminClient)
	mountAdminPositionRoutes(mux, verifier, nil, target, adminClient)
	mountAdminGroupRoutes(mux, verifier, nil, target, adminClient)
	return &foundationTestFixture{t: t, jwks: jwks, backend: backend, mux: mux}
}

// A company administrator manages their own company through every route family, is refused
// on another company, and cannot create companies or org units.
func TestCompanyAdmin_OwnCompanyAllowed_OtherRefused(t *testing.T) {
	client, seen := companyAdminAuthz(t, "co-1")
	f := newCompanyAdminFixture(t, client)
	bearer := f.bearerFor("carol")

	own := []struct{ method, path, body string }{
		{http.MethodPost, "/api/org/admin/members", `{"companyId":"co-1","code":"A","displayName":"A"}`},
		{http.MethodGet, "/api/org/admin/members?companyId=co-1", ""},
		{http.MethodPut, "/api/org/admin/members/mem-1", `{"displayName":"B"}`},
		{http.MethodPost, "/api/org/admin/members/mem-1/link-user", `{"kcSub":"s"}`},
		{http.MethodDelete, "/api/org/admin/members/mem-1/link-user", ""},
		{http.MethodGet, "/api/org/admin/companies/co-1/positions", ""},
		{http.MethodPost, "/api/org/admin/companies/co-1/positions", `{"code":"CFO","title":"CFO"}`},
		{http.MethodPost, "/api/org/admin/positions/pos-1/assignments", `{"memberId":"mem-1"}`},
		{http.MethodPost, "/api/org/admin/assignments/asg-1/end", ""},
		{http.MethodGet, "/api/org/admin/companies/co-1/groups", ""},
		{http.MethodPost, "/api/org/admin/companies/co-1/groups", `{"code":"G","name":"G"}`},
		{http.MethodGet, "/api/org/admin/groups/grp-1/members", ""},
		{http.MethodPost, "/api/org/admin/groups/grp-1/members", `{"memberId":"mem-1"}`},
		{http.MethodDelete, "/api/org/admin/groups/grp-1/members/mem-1", ""},
	}
	for _, rt := range own {
		rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %s = %d, want 200 for the company's administrator; body=%s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
	// Every decision went to authz as a company-scope question about co-1.
	for _, d := range *seen {
		if d["scope"] != "company" || d["companyId"] != "co-1" {
			t.Errorf("decision = %v, want company scope for co-1", d)
		}
	}

	// The same administrator on another company: 403, and org is never called.
	f.backend.setResponse("/internal/org/members/mem-2", http.StatusOK, `{"data":{"id":"mem-2","companyId":"co-2"}}`)
	other := []struct{ method, path, body string }{
		{http.MethodPost, "/api/org/admin/members", `{"companyId":"co-2","code":"A","displayName":"A"}`},
		{http.MethodGet, "/api/org/admin/members?companyId=co-2", ""},
		{http.MethodPut, "/api/org/admin/members/mem-2", `{"displayName":"B"}`},
		{http.MethodGet, "/api/org/admin/companies/co-2/positions", ""},
		{http.MethodPost, "/api/org/admin/companies/co-2/groups", `{"code":"G","name":"G"}`},
	}
	for _, rt := range other {
		before := len(f.backend.calls)
		rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403 on another company; body=%s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
		for _, c := range f.backend.calls[before:] {
			if c.path != "/internal/org/members/mem-2" { // the lookup is fine; the write must not happen
				t.Errorf("%s %s reached org at %s after a refusal", rt.method, rt.path, c.path)
			}
		}
	}

	// Companies and org units stay superadmin work.
	for _, rt := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/org/admin/units", `{"typeKey":"company","code":"x","name":"x"}`},
		{http.MethodGet, "/api/org/admin/units/unit-1", ""},
	} {
		if rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403 for a company administrator", rt.method, rt.path, rec.Code)
		}
	}
}

// The body a company administrator sends reaches org intact after the guard read it.
func TestCompanyAdmin_BodyForwardedAfterGuardReadIt(t *testing.T) {
	client, _ := companyAdminAuthz(t, "co-1")
	f := newCompanyAdminFixture(t, client)
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/org/admin/members", f.bearerFor("carol"), `{"companyId":"co-1","code":"A","displayName":"Alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/org/members" || call.body["displayName"] != "Alice" || call.body["companyId"] != "co-1" {
		t.Fatalf("org received %s %v, want the full body", call.path, call.body)
	}
}

// A malformed or company-less request never reaches authz or org.
func TestCompanyAdmin_UnnamedCompany(t *testing.T) {
	client, seen := companyAdminAuthz(t, "co-1")
	f := newCompanyAdminFixture(t, client)
	bearer := f.bearerFor("carol")
	for _, rt := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/org/admin/members", `{"code":"A"}`},
		{http.MethodPost, "/api/org/admin/members", `not json`},
		{http.MethodGet, "/api/org/admin/members", ""},
	} {
		rec := doFoundationRequest(t, f.mux, rt.method, rt.path, bearer, rt.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s %q = %d, want 400 (the request names no company)", rt.method, rt.path, rt.body, rec.Code)
		}
	}
	if len(*seen) != 0 || len(f.backend.calls) != 0 {
		t.Errorf("authz called %d times, org %d times; want none", len(*seen), len(f.backend.calls))
	}
}

// An unknown resource is 404 before any decision; an org that cannot answer is 503.
func TestCompanyAdmin_ResourceLookupOutcomes(t *testing.T) {
	client, seen := companyAdminAuthz(t, "co-1")
	f := newCompanyAdminFixture(t, client)
	bearer := f.bearerFor("carol")
	f.backend.setResponse("/internal/org/groups/ghost", http.StatusNotFound, `{"error":{"code":"NOT_FOUND","message":"not found"}}`)
	if rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/org/admin/groups/ghost/members", bearer, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown group = %d, want 404", rec.Code)
	}
	f.backend.setResponse("/internal/org/positions/broken", http.StatusInternalServerError, `{}`)
	if rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/org/admin/positions/broken/assignments", bearer, `{"memberId":"m"}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("org failing = %d, want 503", rec.Code)
	}
	f.backend.setResponse("/internal/org/members/nocompany", http.StatusOK, `{"data":{"id":"nocompany"}}`)
	if rec := doFoundationRequest(t, f.mux, http.MethodPut, "/api/org/admin/members/nocompany", bearer, `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("lookup without companyId = %d, want 503", rec.Code)
	}
	if len(*seen) != 0 {
		t.Errorf("authz was asked %d times before the company was known", len(*seen))
	}
}

// The superadmin still passes everywhere through the operator exception (authz answers
// ALLOWED for the company-scope question).
func TestCompanyAdmin_SuperadminStillAllowed(t *testing.T) {
	f := newCompanyAdminFixture(t, allowedAdminClient(t))
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/org/admin/companies/co-9/positions", f.bearerFor("root"), `{"code":"CFO","title":"CFO"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := io.ReadAll(rec.Body); err != nil {
		t.Fatal(err)
	}
}
