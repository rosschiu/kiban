// SPDX-License-Identifier: Apache-2.0

package notification

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
// Mirrors modules/docs/service/chaos_test.go and modules/helpdesk/service/chaos_test.go's
// structure. notification has two structurally different guarded route classes worth proving
// separately: the ordinary withAuth-gated `/api/...` routes (fail-closed 503 on authz-down, same
// as every other module), and the unguarded-by-withAuth `/internal/.../events` S2S endpoint
// (handleSendEvent), which does its OWN authz.Can check inline AND has a real org dependency
// (svc.Org.IsActiveMember) whose failure mode is DIFFERENT from every other module surveyed: an
// org-down recipient is silently SKIPPED (never delivered), not a 503 — proven explicitly below
// as its own distinct "fail-closed-on-delivery, not fail-with-status" pattern.

type notifChaosFixture struct {
	handler http.Handler
	issuer  *testIssuer
}

func newNotifChaosFixture(t *testing.T, authzURL, orgURL string, timeout time.Duration) *notifChaosFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	authzClient := NewAuthzClient(&http.Client{Timeout: timeout}, authzURL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient)
	if orgURL != "" {
		svc.Org = NewOrgClient(&http.Client{Timeout: timeout}, orgURL)
	}
	return &notifChaosFixture{handler: svc.Routes(), issuer: issuer}
}

func (f *notifChaosFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *notifChaosFixture) do(t *testing.T, method, path, bearer, body string) *httptest.ResponseRecorder {
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

func notifAssertAuthzUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
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

func notifDownVariants() []struct {
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

// ---- authz-down: fail-closed on both guarded route classes -------------------------------------

func TestChaos_AuthzDown_ApiRoute_FailsClosed(t *testing.T) {
	for _, tc := range notifDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotifChaosFixture(t, tc.build(t), "", tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			rec := f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels", tok, "")
			notifAssertAuthzUnavailable(t, rec)
		})
	}
}

// TestChaos_AuthzDown_InternalEventsRoute_FailsClosed proves handleSendEvent's OWN inline
// authz.Can check (it doesn't go through withAuth) is just as fail-closed as every withAuth
// route — this is a structurally distinct code path, not a duplicate of the test above.
func TestChaos_AuthzDown_InternalEventsRoute_FailsClosed(t *testing.T) {
	for _, tc := range notifDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotifChaosFixture(t, tc.build(t), "", tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "docs-module-caller")

			rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+companyID+"/events", tok,
				`{"recipientKcSubs":["bob"],"subjectLine":"hi","body":"hi","sourceModule":"docs"}`)
			notifAssertAuthzUnavailable(t, rec)
		})
	}
}

// ---- org-down on the internal events route: fail-closed ON DELIVERY, not fail-with-status ------

// TestChaos_OrgDown_SendEvent_RecipientSkippedNotDelivered proves the distinct pattern flagged
// above: with authz healthy but org down, the request itself still succeeds (200) — but the
// recipient whose membership couldn't be confirmed is SKIPPED, never gets a recipient_state row,
// and is counted in `skipped`, not `sent`. This is fail-closed on the actual guarantee that
// matters (no message delivered to an unconfirmed recipient) even though the HTTP status is not
// itself a 503 — the opposite shape from every other module's org-down proof, and
// worth keeping as its own explicit case rather than folding into the 503 assertions above.
func TestChaos_OrgDown_SendEvent_RecipientSkippedNotDelivered(t *testing.T) {
	for _, tc := range notifDownVariants() {
		t.Run(tc.name, func(t *testing.T) {
			authzSrv := newFakeAuthz(t, map[string]bool{"docs-module-caller": true})
			f := newNotifChaosFixture(t, authzSrv.URL, tc.build(t), tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "docs-module-caller")

			rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+companyID+"/events", tok,
				`{"recipientKcSubs":["bob"],"subjectLine":"hi","body":"hi","sourceModule":"docs"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected the S2S event call itself to succeed (200) even though org is down, got %d: %s", rec.Code, rec.Body.String())
			}
			var out struct {
				Sent    int `json:"sent"`
				Skipped int `json:"skipped"`
			}
			var env struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
			}
			if err := json.Unmarshal(env.Data, &out); err != nil {
				t.Fatalf("decode data: %v (body=%s)", err, rec.Body.String())
			}
			if out.Sent != 0 || out.Skipped != 1 {
				t.Fatalf("sent=%d skipped=%d, want sent=0 skipped=1 (org down -> unconfirmed recipient never delivered)", out.Sent, out.Skipped)
			}
		})
	}
}
