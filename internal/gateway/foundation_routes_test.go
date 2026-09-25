// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// foundationBackendCall records one request the gateway forwarded to a fake downstream
// (authz/org) server — path, query, and (for can/batch-can) the decoded body's actorId — so
// tests can assert exactly what the gateway sent onward, independent of what the response was.
type foundationBackendCall struct {
	path      string
	query     url.Values
	authValue string
	body      map[string]any
}

// newFoundationBackend builds one httptest server standing in for BOTH authz and org's internal
// surfaces (the routes under test never call more than one backend per request, so one process
// is enough) — every request is recorded, and the response for each path is programmable via
// responses (defaults to `{"data":{"ok":true}}`/200 for any path not explicitly configured).
type foundationBackend struct {
	*httptest.Server
	calls     []foundationBackendCall
	responses map[string]struct {
		status int
		body   string
	}
}

func newFoundationBackend(t *testing.T) *foundationBackend {
	t.Helper()
	b := &foundationBackend{responses: map[string]struct {
		status int
		body   string
	}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var decoded map[string]any
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &decoded)
			}
		}
		b.calls = append(b.calls, foundationBackendCall{
			path: r.URL.Path, query: r.URL.Query(), authValue: r.Header.Get("Authorization"), body: decoded,
		})
		resp, ok := b.responses[r.URL.Path]
		if !ok {
			resp.status = http.StatusOK
			resp.body = `{"data":{"ok":true}}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	})
	b.Server = httptest.NewServer(mux)
	t.Cleanup(b.Close)
	return b
}

func (b *foundationBackend) setResponse(path string, status int, body string) {
	b.responses[path] = struct {
		status int
		body   string
	}{status: status, body: body}
}

func (b *foundationBackend) lastCall() foundationBackendCall {
	return b.calls[len(b.calls)-1]
}

// foundationTestFixture wires a real RequireAuth-backed mux (fake JWKS -> real TokenVerifier,
// same as token_test.go) over mountFoundationRoutes, so every test below drives
// the real bearer-validation + subject-injection pipeline end to end, never a hand-built
// AuthContext shortcut.
type foundationTestFixture struct {
	t       *testing.T
	jwks    *fakeJWKSServer
	backend *foundationBackend
	mux     *http.ServeMux
}

func newFoundationTestFixture(t *testing.T, adminClient *AuthzAdminClient) *foundationTestFixture {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	backend := newFoundationBackend(t)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	mux := http.NewServeMux()
	mountFoundationRoutes(mux, verifier, nil, target, target, adminClient)
	return &foundationTestFixture{t: t, jwks: jwks, backend: backend, mux: mux}
}

func (f *foundationTestFixture) bearerFor(subject string) string {
	return f.jwks.signToken(f.t, tokenOpts{subject: subject, audience: []string{testAudience}})
}

func doFoundationRequest(t *testing.T, mux *http.ServeMux, method, target, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, bodyReader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// --- can / batch-can: bearer-gated fixed proxy; subject enforcement lives downstream (authz's
// own bearerSubject + actorId check) and is proven here by relaying its 400, not reimplemented.

func TestFoundationRoutes_Can_RequiresBearer(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/effective-access/can", "", `{"featureKey":"x","scope":"global"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no bearer)", rec.Code)
	}
	if len(f.backend.calls) != 0 {
		t.Fatalf("backend should never be called without a valid bearer, got %d calls", len(f.backend.calls))
	}
}

func TestFoundationRoutes_Can_ForwardsToAuthzWithBearer(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	f.backend.setResponse("/internal/authz/effective-access/can", http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)

	bearer := f.bearerFor("alice")
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/effective-access/can", bearer, `{"featureKey":"x","scope":"global"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/authz/effective-access/can" {
		t.Errorf("forwarded path = %q, want /internal/authz/effective-access/can", call.path)
	}
	if call.authValue != "Bearer "+bearer {
		t.Errorf("Authorization not forwarded verbatim: got %q", call.authValue)
	}
}

// TestFoundationRoutes_Can_BodySubjectRejected proves the subject-injection rule end to end for
// `can`: a body naming a DIFFERENT actor than the bearer is rejected 400 — authz's own real rule
// (canRequestWire.ActorOverride), exercised here through the gateway's proxy, not bypassed or
// re-decided at the edge. The gateway relays authz's 400 unmodified.
func TestFoundationRoutes_Can_BodySubjectRejected(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	f.backend.setResponse("/internal/authz/effective-access/can", http.StatusBadRequest,
		`{"error":{"code":"BAD_REQUEST","message":"actorId must match the bearer subject, or be omitted"}}`)

	bearer := f.bearerFor("alice")
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/effective-access/can", bearer,
		`{"featureKey":"x","scope":"global","actorId":"eve"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body naming another subject", rec.Code)
	}
	call := f.backend.lastCall()
	if call.body["actorId"] != "eve" {
		t.Fatalf("expected the body to be forwarded untouched (actorId=eve) so authz's own check runs; got %v", call.body)
	}
}

// TestFoundationRoutes_BatchCan_BodySubjectRejected is the same proof for batch-can (embeds
// canRequestWire, so the same actorId rule applies).
func TestFoundationRoutes_BatchCan_BodySubjectRejected(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	f.backend.setResponse("/internal/authz/effective-access/batch-can", http.StatusBadRequest,
		`{"error":{"code":"BAD_REQUEST","message":"actorId must match the bearer subject, or be omitted"}}`)

	bearer := f.bearerFor("alice")
	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/effective-access/batch-can", bearer,
		`{"featureKey":"x","scope":"global","actorId":"eve","items":[]}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body naming another subject", rec.Code)
	}
	call := f.backend.lastCall()
	if call.path != "/internal/authz/effective-access/batch-can" {
		t.Errorf("forwarded path = %q, want batch-can", call.path)
	}
	if call.body["actorId"] != "eve" {
		t.Fatalf("expected the body to be forwarded untouched (actorId=eve); got %v", call.body)
	}
}

// --- summary / me/companies: gateway-injected kcSub (these two
// internal endpoints trust a caller-supplied kcSub with NO bearer check at their own layer — the
// gateway is the only thing standing between "any query string" and "the bearer's real
// identity").

func TestFoundationRoutes_Summary_InjectsBearerKcSub_IgnoresClientSupplied(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	bearer := f.bearerFor("alice")

	rec := doFoundationRequest(t, f.mux, http.MethodGet,
		"/api/auth/effective-access/summary?kcSub=eve&companyId=co-1", bearer, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/authz/effective-access/summary" {
		t.Errorf("forwarded path = %q, want summary", call.path)
	}
	if got := call.query.Get("kcSub"); got != "alice" {
		t.Fatalf("kcSub forwarded = %q, want the bearer's own subject %q (client-supplied kcSub=eve must be ignored) — another-user probe must be impossible by construction", got, "alice")
	}
	if got := call.query.Get("companyId"); got != "co-1" {
		t.Errorf("companyId forwarded = %q, want co-1 (non-identity params pass through)", got)
	}
}

func TestFoundationRoutes_Summary_NoClientKcSub_StillInjectsBearer(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	bearer := f.bearerFor("bob")

	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/auth/effective-access/summary", bearer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := f.backend.lastCall().query.Get("kcSub"); got != "bob" {
		t.Fatalf("kcSub forwarded = %q, want bob", got)
	}
}

func TestFoundationRoutes_MeCompanies_InjectsBearerKcSub_IgnoresClientSupplied(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	bearer := f.bearerFor("alice")

	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/org/me/companies?kcSub=eve", bearer, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/org/me/companies" {
		t.Errorf("forwarded path = %q, want /internal/org/me/companies", call.path)
	}
	if got := call.query.Get("kcSub"); got != "alice" {
		t.Fatalf("kcSub forwarded = %q, want the bearer's own subject %q — another-user probe must be impossible by construction", got, "alice")
	}
}

func TestFoundationRoutes_MeCompanies_RequiresBearer(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/org/me/companies", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no bearer)", rec.Code)
	}
}

// --- member directory: gateway-injected kcSub + companyId path forwarding; the
// membership-or-admin gate itself lives downstream in org (proven there, not re-implemented
// here — same division of labor as the can/batch-can proxies above).

func TestFoundationRoutes_MemberDirectory_InjectsBearerKcSub_IgnoresClientSupplied(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	bearer := f.bearerFor("alice")

	rec := doFoundationRequest(t, f.mux, http.MethodGet,
		"/api/org/companies/co-1/members?kcSub=eve&q=bob", bearer, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/org/companies/co-1/members" {
		t.Errorf("forwarded path = %q, want /internal/org/companies/co-1/members", call.path)
	}
	if got := call.query.Get("kcSub"); got != "alice" {
		t.Fatalf("kcSub forwarded = %q, want the bearer's own subject %q (client-supplied kcSub=eve must be ignored)", got, "alice")
	}
	if got := call.query.Get("q"); got != "bob" {
		t.Errorf("q forwarded = %q, want bob (non-identity params pass through)", got)
	}
}

func TestFoundationRoutes_MemberDirectory_RequiresBearer(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/org/companies/co-1/members", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no bearer)", rec.Code)
	}
	if len(f.backend.calls) != 0 {
		t.Fatalf("backend should never be called without a valid bearer, got %d calls", len(f.backend.calls))
	}
}

func TestFoundationRoutes_MemberDirectory_RelaysDownstreamDenial(t *testing.T) {
	f := newFoundationTestFixture(t, nil)
	f.backend.setResponse("/internal/org/companies/co-1/members", http.StatusForbidden,
		`{"error":{"code":"FORBIDDEN","message":"not an active member of this company"}}`)
	bearer := f.bearerFor("stranger")

	rec := doFoundationRequest(t, f.mux, http.MethodGet, "/api/org/companies/co-1/members", bearer, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 relayed from org's own membership gate, body=%s", rec.Code, rec.Body.String())
	}
}

// --- grants: superadmin-guarded (only superadmins grant).

func TestFoundationRoutes_Grants_DeniedForNonAdmin(t *testing.T) {
	adminAuthz := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":false,"reason":"PLATFORM_ROLE_REQUIRED","evidence":[]}}`)
	defer adminAuthz.Close()
	adminClient := NewAuthzAdminClient(adminAuthz.URL)

	f := newFoundationTestFixture(t, adminClient)
	bearer := f.bearerFor("regular-user")

	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/grants", bearer,
		`{"op":"grant","tuples":[{"objectType":"doc","objectId":"1","relation":"viewer","subjectType":"user","subjectId":"bob"}]}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a non-admin caller", rec.Code)
	}
	if len(f.backend.calls) != 0 {
		t.Fatalf("the grants backend must never be called when the superadmin guard denies, got %d calls", len(f.backend.calls))
	}
}

func TestFoundationRoutes_Grants_FailsClosedWhenGuardUncertain(t *testing.T) {
	adminClient := NewAuthzAdminClient("http://127.0.0.1:1") // unreachable -> uncertain -> 503
	f := newFoundationTestFixture(t, adminClient)
	bearer := f.bearerFor("someone")

	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/grants", bearer,
		`{"op":"grant","tuples":[{"objectType":"doc","objectId":"1","relation":"viewer","subjectType":"user","subjectId":"bob"}]}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed on guard uncertainty)", rec.Code)
	}
}

func TestFoundationRoutes_Grants_AllowedForwardsToAuthz(t *testing.T) {
	adminAuthz := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	defer adminAuthz.Close()
	adminClient := NewAuthzAdminClient(adminAuthz.URL)

	f := newFoundationTestFixture(t, adminClient)
	f.backend.setResponse("/internal/authz/grants", http.StatusOK, `{"data":{"status":"ok","count":1}}`)
	bearer := f.bearerFor("superadmin")

	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/auth/grants", bearer,
		`{"op":"grant","tuples":[{"objectType":"doc","objectId":"1","relation":"viewer","subjectType":"user","subjectId":"bob"}]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/authz/grants" {
		t.Errorf("forwarded path = %q, want /internal/authz/grants", call.path)
	}
	if call.authValue != "Bearer "+bearer {
		t.Errorf("Authorization not forwarded verbatim to authz's grants endpoint: got %q", call.authValue)
	}
}

// TestFoundationRoutes_PlatformRoles_ForwardToAuthz proves the two platform-role routes reach
// authz's own /internal/authz/platform-roles endpoints with the bearer forwarded verbatim (the
// revoke's path values carried through), and that authz's own answer (here a 409 for the last
// superadmin) passes back unchanged.
func TestFoundationRoutes_PlatformRoles_ForwardToAuthz(t *testing.T) {
	adminAuthz := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	defer adminAuthz.Close()
	f := newFoundationTestFixture(t, NewAuthzAdminClient(adminAuthz.URL))
	bearer := f.bearerFor("superadmin")

	rec := doFoundationRequest(t, f.mux, http.MethodPost, "/api/platform/admin/platform-roles", bearer, `{"subjectId":"bob","role":"kiban-superadmin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("grant status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	call := f.backend.lastCall()
	if call.path != "/internal/authz/platform-roles" || call.authValue != "Bearer "+bearer || call.body["subjectId"] != "bob" {
		t.Errorf("grant forwarded as path=%q auth=%q body=%v", call.path, call.authValue, call.body)
	}

	f.backend.setResponse("/internal/authz/platform-roles/kiban-superadmin/bob", http.StatusConflict, `{"error":{"code":"CONFLICT","message":"at least one superadmin must remain"}}`)
	rec = doFoundationRequest(t, f.mux, http.MethodDelete, "/api/platform/admin/platform-roles/kiban-superadmin/bob", bearer, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("revoke status = %d, want authz's 409 passed through; body=%s", rec.Code, rec.Body.String())
	}
	if call := f.backend.lastCall(); call.path != "/internal/authz/platform-roles/kiban-superadmin/bob" || call.authValue != "Bearer "+bearer {
		t.Errorf("revoke forwarded as path=%q auth=%q", call.path, call.authValue)
	}
}
