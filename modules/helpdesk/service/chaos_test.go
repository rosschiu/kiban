// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/testchaos"
)

// The shared "dependency down" chaos sweep, built on internal/testchaos.
// Mirrors modules/docs/service/chaos_test.go's structure. Proves authz-down is fail-closed on
// BOTH the plain-member (featureTicketsCreate) and admin (featureHelpdeskManage) withAuth route
// classes, org-down never falls back to stale data on member resolution, and notification-down
// is fail-open BY DESIGN (assignTicketToMember's own fire-and-forget `_ =
// svc.Notification.SendEvent(...)`).

type hdChaosFixture struct {
	handler http.Handler
	issuer  *testIssuer
}

func newHDChaosFixture(t *testing.T, authzURL, orgURL, notifURL string, timeout time.Duration) *hdChaosFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	authzClient := NewAuthzClient(&http.Client{Timeout: timeout}, authzURL)
	orgClient := NewOrgClient(&http.Client{Timeout: timeout}, orgURL)
	notifClient := NewNotificationClient(&http.Client{Timeout: timeout}, notifURL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient, orgClient, notifClient)
	return &hdChaosFixture{handler: svc.Routes(), issuer: issuer}
}

func (f *hdChaosFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *hdChaosFixture) do(t *testing.T, method, path, bearer, body string) *httptest.ResponseRecorder {
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

func hdAssertAuthzUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, rec.Body.String())
	}
	if env.Error.Code != errenv.CodeAuthorizationUnavailable {
		t.Fatalf("error code = %q, want %q", env.Error.Code, errenv.CodeAuthorizationUnavailable)
	}
}

func hdDownVariants() []struct {
	name    string
	build   func(t *testing.T) string
	timeout time.Duration
} {
	return []struct {
		name    string
		build   func(t *testing.T) string
		timeout time.Duration
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }, 2 * time.Second},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }, 2 * time.Second},
		{"slower-than-client-timeout", func(t *testing.T) string { return testchaos.SlowServer(t, time.Second).URL }, 300 * time.Millisecond},
	}
}

// ---- authz-down: fail-closed on every guarded route class -------------------------------------

func TestChaos_AuthzDown_MemberTierRoute_FailsClosed(t *testing.T) {
	for _, tc := range hdDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			orgSrv := newFakeOrgWithPositions(t, nil, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newHDChaosFixture(t, tc.build(t), orgSrv.url, notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/tickets", tok, "")
			hdAssertAuthzUnavailable(t, rec)
		})
	}
}

func TestChaos_AuthzDown_AdminTierRoute_FailsClosed(t *testing.T) {
	for _, tc := range hdDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			orgSrv := newFakeOrgWithPositions(t, nil, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newHDChaosFixture(t, tc.build(t), orgSrv.url, notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "admin")

			rec := f.do(t, http.MethodGet, "/api/helpdesk/v1/companies/"+companyID+"/agents", tok, "")
			hdAssertAuthzUnavailable(t, rec)
		})
	}
}

// ---- org-down: refused, never a fallback to stale/default membership data ---------------------

// TestChaos_OrgDown_CreateTicket_FailsClosed proves handleCreateTicket's org.MemberByKcSub call
// fails closed when org is down — a caller org can't confirm as an active member must never be
// treated as one.
func TestChaos_OrgDown_CreateTicket_FailsClosed(t *testing.T) {
	for _, tc := range hdDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			fa := newFakeAuthz(map[string]bool{"alice": true}, nil)
			authzSrv := fa.server(t)
			notifSrv, _ := newFakeNotification(t)
			f := newHDChaosFixture(t, authzSrv.URL, tc.build(t), notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			rec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", tok,
				`{"title":"broken printer","description":"it's broken"}`)
			// helpdesk conflates the org-transport failure into "not an active member" (403
			// AUTHORIZATION_DENIED) rather than a dedicated 503.
			// What matters for fail-closed correctness: the ticket is REFUSED, never created
			// against unresolved/stale membership data.
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected ticket creation to be refused when org is down, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// ---- notification-down: fail-open BY DESIGN — the business write still succeeds --------------

// TestChaos_NotificationDown_AssignTicket_WriteStillSucceeds proves assignTicketToMember's own
// fire-and-forget notification send does not block the assignment itself.
func TestChaos_NotificationDown_AssignTicket_WriteStillSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) string
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			companyID := uuid.NewString()
			reporterID := uuid.NewString()
			assigneeID := uuid.NewString()
			fa := newFakeAuthz(map[string]bool{"reporter": true, "admin": true}, map[string]bool{"admin": true})
			authzSrv := fa.server(t)
			orgSrv := newFakeOrgWithPositions(t, []fakeOrgMember{
				{id: reporterID, companyID: companyID, kcSub: "reporter", displayName: "Reporter", isActive: true},
				{id: assigneeID, companyID: companyID, kcSub: "assignee", displayName: "Assignee", isActive: true},
			}, nil)
			f := newHDChaosFixture(t, authzSrv.URL, orgSrv.url, tc.build(t), 2*time.Second)
			reporterTok := f.token(t, "reporter")
			adminTok := f.token(t, "admin")

			createRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets", reporterTok,
				`{"title":"broken printer","description":"it's broken"}`)
			if createRec.Code != http.StatusCreated {
				t.Fatalf("create ticket: got %d: %s", createRec.Code, createRec.Body.String())
			}
			var ticket struct {
				ID string `json:"id"`
			}
			decodeHDData(t, createRec, &ticket)

			assignRec := f.do(t, http.MethodPost, "/api/helpdesk/v1/companies/"+companyID+"/tickets/"+ticket.ID+"/assign", adminTok,
				`{"assigneeMemberId":"`+assigneeID+`"}`)
			if assignRec.Code != http.StatusOK {
				t.Fatalf("expected the assignment to SUCCEED despite notification being down (fail-open by design), got %d: %s", assignRec.Code, assignRec.Body.String())
			}
		})
	}
}

func decodeHDData(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		t.Fatalf("decode data: %v (body=%s)", err, rec.Body.String())
	}
}
