// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testopenapi"
)

// newFakeAuthz is a minimal stand-in for authz's `POST /internal/authz/effective-access/can`
// — an httptest server, not a mock of this package's own code (mocks only for genuinely external
// systems; authz is exactly that from this module's point of view).
// It decodes the bearer's own JWT "sub" claim (no signature check needed — the fake stands in
// for a service that already trusts a real, gateway/module-verified bearer) and answers
// allowed=members[sub], mirroring the old fakeOrg's "keyed by kcSub only" test shape exactly.
func newFakeAuthz(t *testing.T, members map[string]bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := subjectFromBearer(r.Header.Get("Authorization"))
		allowed := members[sub]
		reason := "COMPANY_MEMBERSHIP_REQUIRED"
		if allowed {
			reason = "ALLOWED"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// subjectFromBearer decodes a JWT's "sub" claim without verifying it — test-only helper, the
// same trust boundary newFakeAuthz itself stands in for.
func subjectFromBearer(authHeader string) string {
	token := bearerFromHeader(authHeader)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

type httpFixture struct {
	svc     *Service
	handler http.Handler
	issuer  *testIssuer
}

func newHTTPFixture(t *testing.T, members map[string]bool) *httpFixture {
	t.Helper()
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	authzSrv := newFakeAuthz(t, members)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, authzSrv.URL)
	store := newTestStore(t)
	svc := NewService(store, verifier, authzClient)
	return &httpFixture{svc: svc, handler: svc.Routes(), issuer: issuer}
}

func (f *httpFixture) token(t *testing.T, sub string) string {
	return f.issuer.sign(t, testIssuerName, testAudience, sub, time.Now().Add(time.Hour))
}

func (f *httpFixture) do(t *testing.T, method, path, bearer string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	// Every response this file's tests ever record is validated against
	// modules/notification/openapi.yaml's declared schema for the operation the request
	// matched — status code and body shape both.
	if spec, err := testopenapi.LoadModule("notification"); err != nil {
		t.Fatalf("testopenapi.LoadModule(notification): %v", err)
	} else {
		spec.ValidateResponse(t, req, rec)
	}
	return rec
}

func TestHTTP_Health_NoAuthRequired(t *testing.T) {
	f := newHTTPFixture(t, nil)
	rec := f.do(t, http.MethodGet, "/health", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MissingBearer_401(t *testing.T) {
	f := newHTTPFixture(t, nil)
	companyID := uuid.NewString()
	rec := f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels", "", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != "AUTH_TOKEN_INVALID" {
		t.Fatalf("expected AUTH_TOKEN_INVALID, got %q", env.Error.Code)
	}
}

func TestHTTP_NonMember_403(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{}) // caller is a member of nothing
	companyID := uuid.NewString()
	tok := f.token(t, "kcsub-outsider")
	rec := f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels", tok, "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.Error.Code != "AUTHORIZATION_DENIED" {
		t.Fatalf("expected AUTHORIZATION_DENIED, got %q", env.Error.Code)
	}
}

// TestHTTP_AuthzUnavailable_503 proves withAuth's fail-closed branch: when authz
// itself is unreachable, a valid bearer still gets AUTHORIZATION_UNAVAILABLE (503), never treated
// as allowed.
func TestHTTP_AuthzUnavailable_503(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(t.Context(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	unreachableAuthz := NewAuthzClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	store := newTestStore(t)
	svc := NewService(store, verifier, unreachableAuthz)
	f := &httpFixture{svc: svc, handler: svc.Routes(), issuer: issuer}

	companyID := uuid.NewString()
	tok := f.token(t, "kcsub-someone")
	rec := f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels", tok, "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.Error.Code != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("expected AUTHORIZATION_UNAVAILABLE, got %q", env.Error.Code)
	}
}

// TestHTTP_FullFlow drives create channel -> subscribe -> send -> list inbox -> mark read through
// the real HTTP handlers (in-process, real DB) — the same sequence the curl proof exercises
// through the gateway, minus the gateway hop itself (proven separately by the curl proof).
func TestHTTP_FullFlow(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"http-flow","label":"HTTP Flow","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	channelID := createEnv.Data.ID

	rec = f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions", companyID, channelID), tok, "", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("subscribe: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	sendBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":"Hi","body":"There"}`, channelID)
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, sendBody, map[string]string{"Content-Type": "application/json", "Idempotency-Key": "http-flow-1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("send message: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var sendEnv struct {
		Data messageWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sendEnv); err != nil {
		t.Fatalf("decode send response: %v", err)
	}
	messageID := sendEnv.Data.ID

	rec = f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/messages", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list inbox: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var inboxEnv struct {
		Data struct {
			Items []messageWire `json:"items"`
			Total int           `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inboxEnv); err != nil {
		t.Fatalf("decode inbox response: %v", err)
	}
	if inboxEnv.Data.Total != 1 || len(inboxEnv.Data.Items) != 1 || inboxEnv.Data.Items[0].ID != messageID {
		t.Fatalf("expected exactly the sent message in the inbox, got %+v", inboxEnv.Data)
	}
	if inboxEnv.Data.Items[0].ReadAt != nil {
		t.Fatal("expected the message to be unread before mark-read")
	}

	rec = f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/messages/%s/read", companyID, messageID), tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark read: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var readEnv struct {
		Data messageWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &readEnv); err != nil {
		t.Fatalf("decode mark-read response: %v", err)
	}
	if readEnv.Data.ReadAt == nil {
		t.Fatal("expected readAt to be set after mark-read")
	}
}

// TestHTTP_SendMessage_IdempotencyConflict_409 is the HTTP-boundary proof: the SAME
// Idempotency-Key reused with a DIFFERENT payload is 409 IDEMPOTENCY_CONFLICT, not a silent
// replay of the first message.
func TestHTTP_SendMessage_IdempotencyConflict_409(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"idem-conflict-chan","label":"Idem Conflict","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	channelID := createEnv.Data.ID

	headers := map[string]string{"Content-Type": "application/json", "Idempotency-Key": "conflict-key-1"}
	firstBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":"First","body":"Payload A"}`, channelID)
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, firstBody, headers)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first send: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// same key, same payload => replay (200, not a new create)
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, firstBody, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay with identical payload: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// same key, DIFFERENT payload => 409 IDEMPOTENCY_CONFLICT
	conflictingBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":"Second","body":"Payload B"}`, channelID)
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, conflictingBody, headers)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflicting payload reuse: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("expected IDEMPOTENCY_CONFLICT, got %q", errEnv.Error.Code)
	}
}

// TestHTTP_CreateWebhookChannel_SSRFRejected_422 is the HTTP-boundary proof: a webhook
// channel whose target resolves to a disallowed address class is rejected at CREATE time with
// 422 VALIDATION_FAILED, never persisted.
func TestHTTP_CreateWebhookChannel_SSRFRejected_422(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"ssrf-webhook","label":"SSRF Test","kind":"webhook","target":"https://127.0.0.1/hook"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code != "VALIDATION_FAILED" {
		t.Fatalf("expected VALIDATION_FAILED, got %q", errEnv.Error.Code)
	}
}

// TestHTTP_SendMessage_CRLFSubject_422 is the HTTP-boundary proof:
// a subjectLine containing CR/LF — the SMTP header-injection vector — is rejected with 422
// VALIDATION_ERROR (same field-shape code as the existing subjectLine length check — a control
// character is a malformed field, not a domain-policy rejection like VALIDATION_FAILED), never
// persisted or fanned out.
func TestHTTP_SendMessage_CRLFSubject_422(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"crlf-subj","label":"CRLF Subject","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	channelID := createEnv.Data.ID

	sendBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":%q,"body":"There"}`, channelID, "a\r\nBcc: x@y\r\n\r\ninjected")
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, sendBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %q", errEnv.Error.Code)
	}
}

// TestHTTP_Ready_DBReachable covers handleReady (every other test exercises /health, never
// /ready): a working store's pool answers Ping, so /ready is 200 with the same {"status":"ok"}
// shape /health returns.
func TestHTTP_Ready_DBReachable(t *testing.T) {
	f := newHTTPFixture(t, nil)
	rec := f.do(t, http.MethodGet, "/ready", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_ListGetUnsubscribeDeleteChannel_FullFlow covers
// handleListChannels/handleGetChannel/handleUnsubscribe/handleDeleteChannel, which TestHTTP_FullFlow
// above never reaches (create/subscribe/send/list-inbox/mark-read only). Also exercises
// writeStoreError's ErrChannelNotFound branch (GET after DELETE).
func TestHTTP_ListGetUnsubscribeDeleteChannel_FullFlow(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"list-get-del-chan","label":"List Get Del","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	channelID := createEnv.Data.ID

	rec = f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions", companyID, channelID), tok, "", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("subscribe: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// handleListChannels
	rec = f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list channels: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var listEnv struct {
		Data struct {
			Items []channelWire `json:"items"`
			Total int           `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listEnv); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listEnv.Data.Total != 1 || len(listEnv.Data.Items) != 1 || listEnv.Data.Items[0].ID != channelID {
		t.Fatalf("expected exactly the created channel in the list, got %+v", listEnv.Data)
	}

	// handleGetChannel
	rec = f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels/"+channelID, tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get channel: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var getEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &getEnv); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getEnv.Data.ID != channelID {
		t.Fatalf("expected channel %s, got %+v", channelID, getEnv.Data)
	}

	// handleUnsubscribe
	rec = f.do(t, http.MethodDelete, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions/me", companyID, channelID), tok, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unsubscribe: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// handleDeleteChannel
	rec = f.do(t, http.MethodDelete, "/api/notification/v1/companies/"+companyID+"/channels/"+channelID, tok, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete channel: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// writeStoreError's ErrChannelNotFound branch, via handleGetChannel post-delete.
	rec = f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels/"+channelID, tok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get deleted channel: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_BadPathUUID_400 covers parsePathUUID's error branch (every other test only ever
// supplies a valid uuid.NewString()).
func TestHTTP_BadPathUUID_400(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/channels/not-a-uuid", tok, "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code != "BAD_REQUEST" {
		t.Fatalf("expected BAD_REQUEST, got %q", errEnv.Error.Code)
	}
}

// TestHTTP_CreateChannel_BadJSON_400 and TestHTTP_Subscribe_BadJSON_400 cover decodeJSON's
// error branch (every other test supplies either well-formed JSON or no body at all).
func TestHTTP_CreateChannel_BadJSON_400(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, "{not valid json", map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Subscribe_BadJSON_400(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"subscribe-bad-json-chan","label":"Subscribe Bad JSON","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	channelID := createEnv.Data.ID

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions", companyID, channelID), strings.NewReader("{not valid json"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_CreateChannel_ValidationError_422 covers writeStoreError's *ValidationError branch
// through the HTTP boundary (TestCreateChannel_ValidationErrors in store_test.go exercises the
// store layer directly) and, transitively, ValidationError.Error().
func TestHTTP_CreateChannel_ValidationError_422(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"bad-kind-chan","label":"Bad Kind","kind":"sms"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	var errEnv struct {
		Error struct {
			Code    string            `json:"code"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %q", errEnv.Error.Code)
	}
	if errEnv.Error.Details["field"] != "kind" {
		t.Fatalf("expected details.field=kind, got %+v", errEnv.Error.Details)
	}
}
