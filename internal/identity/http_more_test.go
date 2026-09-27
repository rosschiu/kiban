// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// This file covers http.go's mutation handlers' SUCCESS paths (http_test.go's fixture always
// wires NewDenyAllAuthorizer, so every mutation there gets a 503 — proving fail-closed, but
// never exercising the actual mutation logic past the guard), handleReady's failure branch, and writeInternalError's mapping. allowAllAuthorizer is a small
// local test double for AdminAuthorizer; using it here is not weakening any production
// auth/audit behavior (the shipped default stays denyAllAuthorizer, proven separately).

type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return true, nil
}

// newHTTPTestFixtureWithAuthz mirrors http_test.go's newHTTPTestFixture but lets the caller
// choose the AdminAuthorizer, so this file's tests can reach past the fail-closed guard http_test.go
// already proves, into the mutation handlers' own logic.
func newHTTPTestFixtureWithAuthz(t *testing.T, authz AdminAuthorizer, adminUserHandler http.HandlerFunc) *httpTestFixture {
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

	svc := NewService(store, adminClient, verifier, authz, auditWriter)
	return &httpTestFixture{svc: svc, issuer: issuer}
}

func resolveAndGetID(t *testing.T, f *httpTestFixture, kcSub string) uuid.UUID {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	req.Header.Set("Authorization", "Bearer "+f.bearer(t, kcSub, kcSub+"@example.com", kcSub))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup resolve for %s failed: %d %s", kcSub, rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	id, err := uuid.Parse(data["id"].(string))
	if err != nil {
		t.Fatalf("parse resolved id: %v", err)
	}
	return id
}

func TestHTTP_MfaPolicy_SetGlobal_SuccessAndBadBody(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)

	badReq := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", bytes.NewReader([]byte("not json")))
	badRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: status = %d, want 400, body=%s", badRec.Code, badRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	policy, err := f.svc.store.GetGlobalPolicy(context.Background())
	if err != nil || !policy.Required || policy.Method != "otp" {
		t.Fatalf("expected global policy updated to required=true/otp, got %+v (err=%v)", policy, err)
	}
}

// TestHTTP_MfaPolicy_SetGlobal_RequiredWithoutMethodRejected: required=true with an
// empty/unenforceable method is rejected 422 VALIDATION_FAILED at write time, never reaching the
// database.
func TestHTTP_MfaPolicy_SetGlobal_RequiredWithoutMethodRejected(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)

	for _, method := range []string{"", "bogus"} {
		body, _ := json.Marshal(setPolicyRequest{Required: true, Method: method})
		req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("method=%q: status = %d, want 422, body=%s", method, rec.Code, rec.Body.String())
		}
		errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
		if errObj["code"] != "VALIDATION_FAILED" {
			t.Fatalf("method=%q: code = %v, want VALIDATION_FAILED", method, errObj["code"])
		}
	}

	// The rejected write must not have changed the global policy.
	policy, err := f.svc.store.GetGlobalPolicy(context.Background())
	if err != nil {
		t.Fatalf("get global policy: %v", err)
	}
	if policy.Required {
		t.Fatalf("expected the global policy to remain untouched (required=false), got %+v", policy)
	}
}

// TestHTTP_MfaPolicy_SetUser_RequiredWithoutMethodRejected mirrors the global-policy proof above
// for the per-user override endpoint.
func TestHTTP_MfaPolicy_SetUser_RequiredWithoutMethodRejected(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	userID := resolveAndGetID(t, f, "kc-sub-user-policy-invalid")

	body, _ := json.Marshal(setPolicyRequest{Required: true, Method: ""})
	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+userID.String(), bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
	if errObj["code"] != "VALIDATION_FAILED" {
		t.Fatalf("code = %v, want VALIDATION_FAILED", errObj["code"])
	}

	getReq := httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/"+userID.String(), nil)
	getRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(getRec, getReq)
	data := decodeEnvelope(t, getRec)["data"].(map[string]any)
	if data["required"] != false {
		t.Fatalf("expected no override persisted, got %v", data)
	}
}

func TestHTTP_MfaPolicy_UserPolicy_FullLifecycle(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	userID := resolveAndGetID(t, f, "kc-sub-user-policy")

	// GET before any override: falls back to the default global policy.
	getReq := httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/"+userID.String(), nil)
	getRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get user policy: status = %d, want 200, body=%s", getRec.Code, getRec.Body.String())
	}
	data := decodeEnvelope(t, getRec)["data"].(map[string]any)
	if data["required"] != false {
		t.Fatalf("expected default required=false, got %v", data)
	}

	// SET a bad body -> 400.
	badSetReq := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+userID.String(), bytes.NewReader([]byte("{bad")))
	badSetRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(badSetRec, badSetReq)
	if badSetRec.Code != http.StatusBadRequest {
		t.Fatalf("bad set body: status = %d, want 400, body=%s", badSetRec.Code, badSetRec.Body.String())
	}

	// SET a real override.
	setReq := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+userID.String(), bytes.NewReader([]byte(`{"required":true,"method":"passkey"}`)))
	setRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(setRec, setReq)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set user policy: status = %d, want 200, body=%s", setRec.Code, setRec.Body.String())
	}

	getReq2 := httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/"+userID.String(), nil)
	getRec2 := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(getRec2, getReq2)
	data2 := decodeEnvelope(t, getRec2)["data"].(map[string]any)
	if data2["required"] != true || data2["method"] != "passkey" {
		t.Fatalf("expected the override reflected back, got %v", data2)
	}

	// CLEAR it.
	clearReq := httptest.NewRequest(http.MethodDelete, "/internal/identity/mfa-policy/users/"+userID.String(), nil)
	clearRec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear user policy: status = %d, want 200, body=%s", clearRec.Code, clearRec.Body.String())
	}

	getReq3 := httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/"+userID.String(), nil)
	getRec3 := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(getRec3, getReq3)
	data3 := decodeEnvelope(t, getRec3)["data"].(map[string]any)
	if data3["required"] != false {
		t.Fatalf("expected fallback to default after clear, got %v", data3)
	}
}

func TestHTTP_MfaPolicy_UserPolicy_InvalidUserID(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/not-a-uuid", nil),
		httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/not-a-uuid", bytes.NewReader([]byte(`{}`))),
		httptest.NewRequest(http.MethodDelete, "/internal/identity/mfa-policy/users/not-a-uuid", nil),
	} {
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: status = %d, want 400, body=%s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	}
}

// TestHTTP_MfaPolicy_Sync_Success proves handleSyncPolicy's happy path: every resolved user's
// effective policy gets pushed to the (fake) Keycloak admin API, the outcomes come back in the
// response body, and a sync audit row lands.
func TestHTTP_MfaPolicy_Sync_Success(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "some-kc-id"})
		case http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	admin := adminPool(t)
	resolveAndGetID(t, f, "kc-sub-sync-1")

	req := httptest.NewRequest(http.MethodPost, "/internal/identity/mfa-policy/sync", nil)
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("expected exactly 1 sync outcome, got %d: %v", len(data), data)
	}
	outcome := data[0].(map[string]any)
	if outcome["Success"] != true {
		t.Fatalf("expected a successful sync outcome, got %v", outcome)
	}

	var count int
	if err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.identity__events WHERE action = 'identity.mfa_policy.sync'
	`).Scan(&count); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 sync audit row, got %d", count)
	}
}

func TestHTTP_Ready_DatabaseUnavailable(t *testing.T) {
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	pool := identityPool(t)
	store := NewStore(pool)
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), auditWriter)

	pool.Close() // simulate a dead DB before the pool cleanup registered by identityPool runs

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_Resolve_InternalErrorOnDeadStore proves writeInternalError's mapping: a store failure
// (here, a closed pool) on the resolve path surfaces as a generic 500 INTERNAL_ERROR envelope,
// never a raw error message (the handler explicitly discards err from its response, only logging
// concerns keep it as a parameter).
func TestHTTP_Resolve_InternalErrorOnDeadStore(t *testing.T) {
	pool := identityPool(t)
	store := NewStore(pool)
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), auditWriter)
	pool.Close()

	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	req.Header.Set("Authorization", "Bearer "+issuer.sign(t, testIssuerName, testAudience, "kc-sub-dead-pool", "", "", time.Now().Add(time.Hour)))
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Fatalf("code = %v, want INTERNAL_ERROR", errObj["code"])
	}
}

// TestHTTP_Authenticate_InvalidTokenIsRejected covers authenticate's Verify-fails branch — the
// "no bearer at all" case is TestHTTP_Resolve_RequiresBearer's job; this is the "a bearer was
// supplied but doesn't validate" case (garbage, not a real JWS).
func TestHTTP_Authenticate_InvalidTokenIsRejected(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/identity/resolve", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj := body["error"].(map[string]any)
	if errObj["code"] != "AUTH_TOKEN_INVALID" {
		t.Fatalf("code = %v, want AUTH_TOKEN_INVALID", errObj["code"])
	}
}

// TestHTTP_UserState_InternalErrorOnDeadAdmin covers handleUserState's writeInternalError branch
// (ResolveUserState fails for a reason other than ErrUserNotFound): a closed pool after the user
// already resolved.
func TestHTTP_UserState_InternalErrorOnDeadAdmin(t *testing.T) {
	setupFixture := newHTTPTestFixture(t, nil)
	resolveAndGetID(t, setupFixture, "kc-sub-state-dead-pool")

	pool := identityPool(t)
	store := NewStore(pool)
	verifier, err := NewTokenVerifier(context.Background(), setupFixture.issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), auditWriter)
	pool.Close()

	req := httptest.NewRequest(http.MethodGet, "/internal/identity/users/kc-sub-state-dead-pool/state", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AuthorizeGuard_AuditDenialBeginTxFails covers auditDenial's own begin-tx-error branch
// (a no-op early return, distinct from the audit-Record-error branch already covered by
// TestHTTP_SetUserPolicy_FailClosed503AndAudited's successful denial write): a closed pool means
// svc.store.pool.Begin itself fails, so auditDenial returns having written nothing — the 503
// must still be the caller-visible outcome (auditing a denial is best-effort, never load-bearing
// for the fail-closed guard itself).
func TestHTTP_AuthorizeGuard_AuditDenialBeginTxFails(t *testing.T) {
	setupFixture := newHTTPTestFixture(t, nil)
	pool := identityPool(t)
	store := NewStore(pool)
	verifier, err := NewTokenVerifier(context.Background(), setupFixture.issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), auditWriter)
	pool.Close()

	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+uuid.New().String(), bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed must hold even when the denial audit write itself fails), body=%s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_AuthorizeGuard_AuditDenialRecordFails covers auditDenial's audit-Record-error branch
// (the tx opens fine, the append itself fails because the writer targets a table that does not
// exist): the denial is still 503, the guard never depends on its own audit write succeeding.
func TestHTTP_AuthorizeGuard_AuditDenialRecordFails(t *testing.T) {
	setupFixture := newHTTPTestFixture(t, nil)
	store := NewStore(identityPool(t))
	verifier, err := NewTokenVerifier(context.Background(), setupFixture.issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	brokenWriter, err := audit.NewWriter("audit.identity__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, NewDenyAllAuthorizer(), brokenWriter)

	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+uuid.New().String(), bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed must hold even when the denial audit append fails), body=%s", rec.Code, rec.Body.String())
	}
}

// newDeadPoolServiceWithAuthz builds a Service wired to allowAllAuthorizer (so authorize()'s
// in-memory guard passes) but a CLOSED identity pool, so any store call the handler under test
// makes fails as a generic DB error — this is the shared setup for the rest of this file's
// writeInternalError branch proofs on the MFA-policy mutation handlers,
// which all guard on authorize() (no DB) before ever touching the store.
func newDeadPoolServiceWithAuthz(t *testing.T) *Service {
	t.Helper()
	issuer := newTestIssuer(t)
	pool := identityPool(t)
	store := NewStore(pool)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	adminClient := NewAdminClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, adminClient, verifier, allowAllAuthorizer{}, auditWriter)
	pool.Close()
	return svc
}

func TestHTTP_MutationHandlers_InternalErrorOnDeadStore(t *testing.T) {
	someID := uuid.New().String()

	cases := []struct {
		name string
		req  func() *http.Request
	}{
		{"GetGlobalPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/global", nil)
		}},
		{"SetGlobalPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
		}},
		{"GetUserPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/internal/identity/mfa-policy/users/"+someID, nil)
		}},
		{"SetUserPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/users/"+someID, bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
		}},
		{"ClearUserPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodDelete, "/internal/identity/mfa-policy/users/"+someID, nil)
		}},
		{"SyncPolicy", func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/internal/identity/mfa-policy/sync", nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newDeadPoolServiceWithAuthz(t)
			rec := httptest.NewRecorder()
			svc.Routes().ServeHTTP(rec, tc.req())
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
			}
			body := decodeEnvelope(t, rec)
			errObj := body["error"].(map[string]any)
			if errObj["code"] != "INTERNAL_ERROR" {
				t.Fatalf("code = %v, want INTERNAL_ERROR", errObj["code"])
			}
		})
	}
}

// TestActorFor_NonEmptySubject covers actorFor's other branch — every current HTTP handler
// constructs an empty AuthContext{} (no admin-caller identity source yet, per handleGrantRole's
// own comment), so the "authCtx.Subject != ”" branch is otherwise unreachable from this
// package's HTTP-level tests; it's still real behavior worth a direct unit proof.
func TestActorFor_NonEmptySubject(t *testing.T) {
	if got := actorFor(AuthContext{Subject: "kc-sub-actor"}); got != "kc-sub-actor" {
		t.Fatalf("actorFor with a non-empty subject = %q, want %q", got, "kc-sub-actor")
	}
	if got := actorFor(AuthContext{RawBearer: "Bearer " + unsignedBearerForActorTest(t, "kc-from-bearer")}); got != "kc-from-bearer" {
		t.Errorf("actorFor(bearer only) = %q, want kc-from-bearer", got)
	}
	if got := actorFor(AuthContext{RawBearer: "Bearer garbage"}); got != "unauthenticated" {
		t.Errorf("actorFor(garbage bearer) = %q, want unauthenticated", got)
	}
	if got := actorFor(AuthContext{}); got != "unauthenticated" {
		t.Fatalf("actorFor with an empty subject = %q, want %q", got, "unauthenticated")
	}
}

func unsignedBearerForActorTest(t *testing.T, sub string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Subject(sub).Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
