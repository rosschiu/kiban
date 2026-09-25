// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

const testAudience = "kiban-api"
const testIssuerName = "test-issuer"

// httpTestFixture bundles a Service wired to real DB fixtures plus a fake Keycloak (JWKS +
// admin API) so http_test.go can exercise the full bearer-validated request path without a live
// Keycloak (that live proof is live_test.go's job).
type httpTestFixture struct {
	svc    *Service
	issuer *testIssuer
}

func newHTTPTestFixture(t *testing.T, adminUserHandler http.HandlerFunc) *httpTestFixture {
	t.Helper()
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)

	store := NewStore(identityPool(t))
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	var adminClient *AdminClient
	if adminUserHandler != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/realms/kc-realm/protocol/openid-connect/token", okTokenHandler)
		mux.HandleFunc("/admin/realms/kc-realm/users/", adminUserHandler)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		adminClient = NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "kc-realm", "identity-service", "secret")
	} else {
		adminClient = NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	}

	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}

	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), auditWriter)
	return &httpTestFixture{svc: svc, issuer: issuer}
}

func (f *httpTestFixture) bearer(t *testing.T, sub, email, username string) string {
	t.Helper()
	return f.issuer.sign(t, testIssuerName, testAudience, sub, email, username, time.Now().Add(time.Hour))
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body not valid JSON: %v (%s)", err, rec.Body.String())
	}
	return body
}

func TestHTTP_Resolve_RequiresBearer(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "AUTH_TOKEN_MISSING" {
		t.Errorf("code = %v, want AUTH_TOKEN_MISSING", errObj["code"])
	}
}

func TestHTTP_Resolve_RejectsCallerIdentityHeader(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	req.Header.Set("X-User-Id", "spoofed")
	req.Header.Set("Authorization", "Bearer "+f.bearer(t, "kc-sub-x", "x@example.com", "x"))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Resolve_Success(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	req.Header.Set("Authorization", "Bearer "+f.bearer(t, "kc-sub-resolve", "r@example.com", "resolver"))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data := body["data"].(map[string]any)
	if data["kcSub"] != "kc-sub-resolve" || data["lifecycle"] != "active" {
		t.Fatalf("unexpected resolved user: %v", data)
	}
}

func TestHTTP_UserState_NotFound(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/internal/identity/users/kc-sub-ghost/state", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_UserState_Success(t *testing.T) {
	f := newHTTPTestFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": true})
	})

	resolveReq := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	resolveReq.Header.Set("Authorization", "Bearer "+f.bearer(t, "kc-sub-state", "s@example.com", "state"))
	resolveRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(resolveRec, resolveReq)
	if resolveRec.Code != http.StatusOK {
		t.Fatalf("setup resolve failed: %d %s", resolveRec.Code, resolveRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/identity/users/kc-sub-state/state", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data := body["data"].(map[string]any)
	if data["lifecycle"] != "active" || data["kcEnabled"] != "true" {
		t.Fatalf("unexpected state: %v", data)
	}
}

// TestHTTP_SetUserPolicy_FailClosed503AndAudited mirrors registry's
// TestHTTP_Enable_FailClosed503AndAudited: the denyAllAuthorizer refuses with 503, and the
// denial is itself audited.
func TestHTTP_SetUserPolicy_FailClosed503AndAudited(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	admin := adminPool(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+userID.String(), strings.NewReader(`{"required":true,"method":"otp"}`))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "AUTHORIZATION_UNAVAILABLE" {
		t.Errorf("code = %v, want AUTHORIZATION_UNAVAILABLE", errObj["code"])
	}

	var count int
	err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.identity__events
		WHERE subject = $1 AND action = 'identity.mfa_policy.set_user' AND payload->>'denied' = 'true'
	`, "user:"+userID.String()).Scan(&count)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 denial audit row, got %d", count)
	}
}

func TestHTTP_MfaPolicy_GetGlobal_Default(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/global", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data := body["data"].(map[string]any)
	if data["required"] != false {
		t.Fatalf("expected default global policy required=false, got %v", data)
	}
}

func TestHTTP_MfaPolicy_SetGlobal_FailClosed503(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	reqBody := `{"required":true,"method":"otp"}`
	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}

	// Fail-closed: the policy must NOT have changed.
	policy, err := f.svc.store.GetGlobalPolicy(context.Background())
	if err != nil {
		t.Fatalf("get global policy: %v", err)
	}
	if policy.Required {
		t.Errorf("global policy changed despite the 503 fail-closed guard: %+v", policy)
	}
}

func TestHTTP_HealthAndReady(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	for _, path := range []string{"/health", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200, body=%s", path, rec.Code, rec.Body.String())
		}
	}
}
