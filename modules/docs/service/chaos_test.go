// SPDX-License-Identifier: Apache-2.0

package docs

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
// Proves two directions explicitly for docs: authz-down is fail-closed on BOTH guarded route
// classes (withAuth feature-only AND withObjectAuth per-document), org-down never falls back to
// stale data, and notification-down is fail-open BY DESIGN (handleCreateShare's own doc comment:
// "non-fatal if notification is unreachable").

// chaosFixture builds a docs Service wired to independently-controllable authz/org/notification
// base URLs, so each test below can put exactly one dependency "down" while the others stay
// healthy — proving the failure is attributable to that one dependency, not an artifact of the
// whole fixture being broken.
type chaosFixture struct {
	handler http.Handler
	issuer  *testIssuer
}

func newChaosFixture(t *testing.T, authzURL, orgURL, notifURL string, timeout time.Duration) *chaosFixture {
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
	return &chaosFixture{handler: svc.Routes(), issuer: issuer}
}

func (f *chaosFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *chaosFixture) do(t *testing.T, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func assertAuthzUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
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

// ---- authz-down: fail-closed on every guarded route class -------------------------------------

func TestChaos_AuthzDown_WithAuthRoute_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   func(t *testing.T) string
		timeout time.Duration
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }, 2 * time.Second},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }, 2 * time.Second},
		{"slower-than-client-timeout", func(t *testing.T) string { return testchaos.SlowServer(t, time.Second).URL }, 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgSrv := newFakeOrg(t, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newChaosFixture(t, tc.build(t), orgSrv.URL, notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents", tok, "")
			assertAuthzUnavailable(t, rec)
		})
	}
}

func TestChaos_AuthzDown_WithObjectAuthRoute_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   func(t *testing.T) string
		timeout time.Duration
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }, 2 * time.Second},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }, 2 * time.Second},
		{"slower-than-client-timeout", func(t *testing.T) string { return testchaos.SlowServer(t, time.Second).URL }, 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgSrv := newFakeOrg(t, nil)
			notifSrv, _ := newFakeNotification(t)
			f := newChaosFixture(t, tc.build(t), orgSrv.URL, notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			docID := uuid.NewString()
			tok := f.token(t, "alice")

			// The object-auth check happens before any document existence lookup (see
			// withObjectAuth's own doc comment), so a nonexistent docID still proves the
			// fail-closed branch without needing a real document to exist first.
			rec := f.do(t, http.MethodGet, "/api/docs/v1/companies/"+companyID+"/documents/"+docID, tok, "")
			assertAuthzUnavailable(t, rec)
		})
	}
}

// ---- org-down: 503-equivalent refusal, never a fallback to stale/default data -----------------

// TestChaos_OrgDown_CreateShare_FailsClosed proves handleCreateShare's org.GetMember call fails
// closed rather than silently treating an unresolvable member as valid or falling back to any
// cached/stale membership fact — org is the ONLY source of truth for member facts
// (modules consume foundation facts through APIs only).
func TestChaos_OrgDown_CreateShare_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   func(t *testing.T) string
		timeout time.Duration
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }, 2 * time.Second},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }, 2 * time.Second},
		{"slower-than-client-timeout", func(t *testing.T) string { return testchaos.SlowServer(t, time.Second).URL }, 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fa := newFakeAuthz(map[string]bool{"alice": true}, nil)
			authzSrv := fa.server(t)
			notifSrv, _ := newFakeNotification(t)
			f := newChaosFixture(t, authzSrv.URL, tc.build(t), notifSrv.URL, tc.timeout)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", tok, `{"title":"D","body":"b"}`)
			if createRec.Code != http.StatusCreated {
				t.Fatalf("create document (org not yet on this path): got %d: %s", createRec.Code, createRec.Body.String())
			}
			var doc documentWire
			decodeData(t, createRec, &doc)

			rec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", tok,
				`{"memberId":"`+uuid.NewString()+`","relation":"viewer"}`)
			// docs conflates an org-transport failure into the "no linked user" business
			// validation code (422 VALIDATION_FAILED) rather than a dedicated 503. What matters for fail-closed correctness: the share is REFUSED,
			// never silently granted against unresolved/stale membership data.
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected the share to be refused when org is down, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// ---- notification-down: fail-open BY DESIGN — the business write still succeeds --------------

// TestChaos_NotificationDown_CreateShare_WriteStillSucceeds proves the documented non-fatal
// contract: handleCreateShare's own doc comment says "non-fatal if notification is unreachable
// (sharing must not depend on notification availability)" — this is the OTHER direction
// from authz/org: fail-OPEN by design, not a bug.
func TestChaos_NotificationDown_CreateShare_WriteStillSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) string
	}{
		{"connection-refused", func(t *testing.T) string { return testchaos.RefusedURL() }},
		{"server-error-500", func(t *testing.T) string { return testchaos.ErrorServer(t, http.StatusInternalServerError).URL }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memberID := uuid.NewString()
			fa := newFakeAuthz(map[string]bool{"alice": true}, nil)
			authzSrv := fa.server(t)
			orgSrv := newFakeOrg(t, []fakeOrgMember{{id: memberID, kcSub: "bob", displayName: "Bob", isActive: true}})
			f := newChaosFixture(t, authzSrv.URL, orgSrv.URL, tc.build(t), 2*time.Second)
			companyID := uuid.NewString()
			tok := f.token(t, "alice")

			createRec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents", tok, `{"title":"D","body":"b"}`)
			if createRec.Code != http.StatusCreated {
				t.Fatalf("create document: got %d: %s", createRec.Code, createRec.Body.String())
			}
			var doc documentWire
			decodeData(t, createRec, &doc)

			rec := f.do(t, http.MethodPost, "/api/docs/v1/companies/"+companyID+"/documents/"+doc.ID+"/shares", tok,
				`{"memberId":"`+memberID+`","relation":"viewer"}`)
			if rec.Code != http.StatusCreated {
				t.Fatalf("expected the share write to SUCCEED despite notification being down (fail-open by design), got %d: %s", rec.Code, rec.Body.String())
			}
			var sh shareWire
			decodeData(t, rec, &sh)
			if sh.Relation != "viewer" {
				t.Fatalf("share = %+v, want relation=viewer", sh)
			}
		})
	}
}
