// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testchaos"
)

// The shared internal/testchaos "dependency down" helper, applied to timesheet.
// modules/timesheet/service/http_more_test.go's tests (TestHTTP_Authz_Unavailable_503,
// TestHTTP_ResolveCallerMember_OrgUnavailable_503, TestHTTP_AssignApprover_AuthzGrantUnavailable_503)
// prove authz-down and org-down fail-closed via hand-rolled `httptest.NewServer` down-servers on
// the config/entries/approvers routes. This file builds on those: (1) uses the shared
// testchaos.RefusedURL/ErrorServer/SlowServer helper so the down-server SHAPE is defined once
// platform-wide, (2) adds the slower-than-client-timeout shape (those tests use
// connection-refused/500 only), and (3) covers a THIRD guarded route class:
// featureProjectsManage (handleCreateProject). timesheet has no notification client at all (see
// modules/timesheet/service/http.go's Service struct), so there is no fail-open-by-design direction
// to prove here, unlike docs/helpdesk.

func newChaosHTTPFixture(t *testing.T, authzURL, orgURL string, timeout time.Duration) *httpFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	authzClient := NewAuthzClient(&http.Client{Timeout: timeout}, authzURL)
	orgClient := NewOrgClient(&http.Client{Timeout: timeout}, orgURL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient)
	return &httpFixture{handler: svc.Routes(), issuer: issuer}
}

func chaosDo(t *testing.T, f *httpFixture, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// TestChaos_AuthzDown_SlowerThanClientTimeout_FailsClosed adds the timeout shape the hand-rolled
// down-servers in http_more_test.go don't exercise (they use connection-refused/500 only) — proves
// withAuth's fail-closed branch also holds when authz is up but wedged past the client's own
// timeout, not just when it's outright unreachable or erroring.
func TestChaos_AuthzDown_SlowerThanClientTimeout_FailsClosed(t *testing.T) {
	slowAuthz := testchaos.SlowServer(t, time.Second)
	orgSrv := newFakeOrg(t, nil)

	f := newChaosHTTPFixture(t, slowAuthz.URL, orgSrv.URL, 300*time.Millisecond)
	companyID := uuid.New().String()
	tok := f.token(t, "kcsub-someone")

	rec := chaosDo(t, f, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/config", tok, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestChaos_OrgDown_SlowerThanClientTimeout_FailsClosed is resolveCallerMember's timeout-shape
// sibling to TestHTTP_ResolveCallerMember_OrgUnavailable_503 (connection-refused only).
func TestChaos_OrgDown_SlowerThanClientTimeout_FailsClosed(t *testing.T) {
	memberSub := "kcsub-member"
	authzSrv := newFakeAuthz(t, map[string]bool{memberSub: true}, nil)
	slowOrg := testchaos.SlowServer(t, time.Second)

	f := newChaosHTTPFixture(t, authzSrv.URL, slowOrg.URL, 300*time.Millisecond)
	companyID := uuid.New().String()
	tok := f.token(t, memberSub)

	rec := chaosDo(t, f, http.MethodGet, "/api/timesheet/v1/companies/"+companyID+"/entries?weekStart=2026-08-10", tok, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErr(t, rec); e.Error.Code != "INTERNAL_ERROR" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestChaos_AuthzDown_ProjectsManageRoute_FailsClosed covers featureProjectsManage
// (handleCreateProject) — a guarded route class none of http_more_test.go's authz-down tests exercise
// (they covered featureEntriesManageOwn/config and the approvers grant-write path only).
func TestChaos_AuthzDown_ProjectsManageRoute_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) string
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgSrv := newFakeOrg(t, nil)
			f := newChaosHTTPFixture(t, tc.build(t), orgSrv.URL, 2*time.Second)
			companyID := uuid.New().String()
			tok := f.token(t, "kcsub-admin")

			rec := chaosDo(t, f, http.MethodPost, "/api/timesheet/v1/companies/"+companyID+"/projects", tok, `{"name":"Project X"}`)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
			}
			if e := decodeErr(t, rec); e.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
				t.Fatalf("error = %+v", e.Error)
			}
		})
	}
}
