// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/url"
	"testing"
)

// An app's backend (azp = its registered service client id) reaches the member-by-subject
// lookup and the grants route, forwarded to the foundation services; a browser user without
// superadmin standing does not.
func TestFoundationRoutes_AppBackend(t *testing.T) {
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{ModuleKey: "tokidesk", Installed: true, Enabled: true, External: true, ServiceClientID: "tokidesk-backend"}}, nil)
	catalog := NewCatalogClient(reg.server.URL, nil)

	mux := http.NewServeMux()
	mountFoundationRoutes(mux, verifier, nil, target, target, nil, catalog)

	appBearer := jwks.signToken(t, tokenOpts{subject: "sa-tokidesk", audience: []string{testAudience}, azp: "tokidesk-backend"})
	userBearer := jwks.signToken(t, tokenOpts{subject: "alice", audience: []string{testAudience}, azp: "kiban-frontend"})

	rec := doFoundationRequest(t, mux, http.MethodGet, "/api/org/companies/co-1/members/by-subject/alice", appBearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("app member lookup: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if n := len(backend.calls); n != 1 || backend.calls[0].path != "/internal/org/companies/co-1/members/by-kcsub/alice" {
		t.Fatalf("backend calls = %+v, want one call to the internal by-kcsub route", backend.calls)
	}

	rec = doFoundationRequest(t, mux, http.MethodPost, "/api/auth/grants", appBearer,
		`{"op":"grant","companyId":"co-1","tuples":[{"objectType":"ticket","objectId":"1","relation":"viewer","subjectType":"user","subjectId":"alice"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("app grants: status %d, want 200 (authz decides the rest): %s", rec.Code, rec.Body.String())
	}
	if n := len(backend.calls); n != 2 || backend.calls[1].path != "/internal/authz/grants" {
		t.Fatalf("backend calls = %+v, want the grants call forwarded", backend.calls)
	}

	rec = doFoundationRequest(t, mux, http.MethodGet, "/api/org/companies/co-1/members/by-subject/alice", userBearer, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("browser user with no admin client: status %d, want 503 (fail closed)", rec.Code)
	}
	if len(backend.calls) != 2 {
		t.Fatalf("backend must not be called for a refused caller, calls = %+v", backend.calls)
	}
}
