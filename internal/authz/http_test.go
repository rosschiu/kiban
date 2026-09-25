// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

// This file covers http.go's HTTP handler surface. Every handler is exercised via a real
// net/http/httptest round trip against a real
// Service wired to: the live authz Postgres (authzPool, same helper grant_test.go already
// established), a real audit.Writer, a real TokenVerifier backed by a real JWKS httptest server
// (github.com/lestrrat-go/jwx/v3 pattern ported from internal/identity/token_test.go /
// internal/gateway/token_test.go — each package duplicates the small infra helper),
// and fake identity/registry/org HTTP servers standing in for those other services' real wire
// contracts (mocks only for the genuinely-external-to-this-test-run services —
// company_scope_test.go/clients_test.go already establish this pattern for identity/org).

// --- JWKS/JWT test issuer (ported from internal/identity/token_test.go) ---

const (
	testIssuerName = "https://kc.test.example/realms/kiban"
	testAudience   = "kiban-authz"
)

type testIssuer struct {
	jwksServer *httptest.Server
	privateKey jwk.Key
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, "test-key"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add public key to set: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return &testIssuer{jwksServer: srv, privateKey: priv}
}

// signNoSubject mints a validly-signed token that carries no "sub" claim, to exercise
// TokenVerifier.Verify's post-parse "sub missing/empty" rejection branch.
func (ti *testIssuer) signNoSubject(t *testing.T, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(testIssuerName).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(exp).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), ti.privateKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func (ti *testIssuer) sign(t *testing.T, sub string, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(testIssuerName).
		Audience([]string{testAudience}).
		Subject(sub).
		IssuedAt(time.Now()).
		Expiration(exp).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), ti.privateKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// --- fake registry / org servers (standing in for real identity/registry/org services) ---

func fakeRegistryServer(t *testing.T, moduleEnabled map[string]bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/platform/capabilities/{module}", func(w http.ResponseWriter, r *http.Request) {
		mod := r.PathValue("module")
		writeTestData(w, map[string]bool{"enabled": moduleEnabled[mod]})
	})
	mux.HandleFunc("GET /api/platform/capabilities", func(w http.ResponseWriter, r *http.Request) {
		list := make([]map[string]any, 0, len(moduleEnabled))
		for k, v := range moduleEnabled {
			list = append(list, map[string]any{"module": k, "enabled": v})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": list})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type fakeCompanyFact struct{ exists, active bool }
type fakeMembershipFact struct{ isMember, active bool }

func fakeOrgServer(t *testing.T, companies map[string]fakeCompanyFact, memberships map[string]fakeMembershipFact) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/org/companies/{companyID}/state", func(w http.ResponseWriter, r *http.Request) {
		f := companies[r.PathValue("companyID")]
		writeTestData(w, map[string]bool{"exists": f.exists, "isActive": f.active})
	})
	mux.HandleFunc("GET /internal/org/companies/{companyID}/members/by-kcsub/{kcSub}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("companyID") + "/" + r.PathValue("kcSub")
		f := memberships[key]
		writeTestData(w, map[string]any{"isMember": f.isMember, "isActive": f.active})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// --- Service fixture ---

// buildHTTPService wires a real Service: live authz Postgres, real audit.Writer, a real
// TokenVerifier against a fresh JWKS server, and fake identity/registry/org servers. Every
// kcSub in identityRoles is a known active user; the ones listing "kiban-superadmin" get the
// real `system:platform#superadmin` tuple (the platform role's only record) seeded in the live
// store for the test's lifetime.
func buildHTTPService(t *testing.T, identityRoles map[string][]string, moduleEnabled map[string]bool,
	companies map[string]fakeCompanyFact, memberships map[string]fakeMembershipFact, debugCheck bool,
) (*Service, *testIssuer, *pgxpool.Pool) {
	t.Helper()
	pool := authzPool(t)

	auditWriter, err := audit.NewWriter("audit.authz__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}

	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	identitySrv := fakeIdentityServer(t, identityRoles)
	identityClient := NewIdentityClient(&http.Client{Timeout: 2 * time.Second}, identitySrv.URL)
	for kcSub, roles := range identityRoles {
		for _, role := range roles {
			if role == store.PlatformRoleSuperadmin {
				seedSuperadminTuple(t, pool, kcSub)
			}
		}
	}

	registrySrv := fakeRegistryServer(t, moduleEnabled)
	registryClient := NewRegistryClient(&http.Client{Timeout: 2 * time.Second}, registrySrv.URL)

	orgSrv := fakeOrgServer(t, companies, memberships)
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, orgSrv.URL)

	svc := &Service{
		Pool:         pool,
		Audit:        auditWriter,
		KnownEnabled: registryClient.KnownEnabled,
		Verifier:     verifier,
		DebugCheck:   debugCheck,
		Identity:     identityClient,
		Registry:     registryClient,
		Org:          orgClient,
	}
	return svc, issuer, pool
}

// seedSuperadminTuple grants `system:platform#superadmin` to kcSub through the real store and
// removes it (plus its ledger rows) at cleanup.
func seedSuperadminTuple(t *testing.T, pool *pgxpool.Pool, kcSub string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-fixture", "", store.SuperadminTuple(kcSub)); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant superadmin tuple: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_type = 'system' AND subject_id = $1`, kcSub)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_type = 'system' AND subject_id = $1`, kcSub)
	})
}

// seedCompanyAdminFragment grants companyID#admin to subjectID via the real transactional
// store.Grant, so handleCan/handleBatchCan/handleDebugCheck exercise a REAL engine relation
// check. "company" is a platform BASE type, always loaded (internal/authz/engine.BaseModel) —
// its #admin relation ("this": true, among other branches) is effective with zero module
// fragments, so this needs no synthetic per-test "company" model fragment (the base-type-
// redeclaration reject would refuse one). moduleKey is kept as a parameter for call-site
// compatibility; nothing here writes an authz.model_fragment row.
func seedCompanyAdminFragment(t *testing.T, pool *pgxpool.Pool, moduleKey, companyID, subjectID string) {
	t.Helper()
	ctx := context.Background()
	_ = moduleKey

	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id = $1`, companyID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-fixture", "", store.Tuple{
		ObjectType: "company", ObjectID: companyID, Relation: "admin", SubjectType: "user", SubjectID: subjectID,
	}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, companyID)
	})
}

func mustJSON(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(b)
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

// --- health / ready ---

func TestHandleHealth(t *testing.T) {
	svc, _, _ := buildHTTPService(t, nil, nil, nil, nil, false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	svc.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]map[string]string
	decodeBody(t, rec, &body)
	if body["data"]["status"] != "ok" {
		t.Fatalf("body = %+v, want status=ok", body)
	}
}

func TestHandleReady(t *testing.T) {
	svc, _, _ := buildHTTPService(t, nil, nil, nil, nil, false)

	t.Run("pool reachable: 200", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("pool unreachable: 503", func(t *testing.T) {
		// A dedicated pool, closed before the request, so this sub-test doesn't disturb the
		// shared authzPool(t) other sub-tests/tests still need.
		closedPool := authzPool(t)
		closedPool.Close()
		svc2 := &Service{Pool: closedPool}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		svc2.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		var body map[string]map[string]string
		decodeBody(t, rec, &body)
		if body["error"]["code"] != "AUTHORIZATION_UNAVAILABLE" {
			t.Fatalf("error code = %q, want AUTHORIZATION_UNAVAILABLE", body["error"]["code"])
		}
	})
}

// --- bearerSubject / auth gate, exercised through handleCan (any bearer-gated handler works) ---

func TestBearerSubjectRejections(t *testing.T) {
	svc, issuer, _ := buildHTTPService(t, map[string][]string{"u1": nil}, map[string]bool{"m1": true}, nil, nil, false)

	cases := []struct {
		name       string
		authHeader string
		wantCode   string
	}{
		{"missing header", "", "AUTH_TOKEN_MISSING"},
		{"missing Bearer prefix", "Basic abc123", "AUTH_TOKEN_MISSING"},
		{"garbage token", "Bearer not-a-jwt", "AUTH_TOKEN_INVALID"},
		{"expired token", "Bearer " + issuer.sign(t, "u1", time.Now().Add(-time.Hour)), "AUTH_TOKEN_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, map[string]any{}))
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			svc.Routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			var body map[string]map[string]string
			decodeBody(t, rec, &body)
			if body["error"]["code"] != tc.wantCode {
				t.Fatalf("error code = %q, want %q", body["error"]["code"], tc.wantCode)
			}
		})
	}
}

// --- handleCan ---

func TestHandleCan(t *testing.T) {
	const moduleKey, companyID, adminSub, otherSub, globalSub = "http-can-mod", "http-can-co", "http-can-admin", "http-can-nobody", "http-can-global-admin"

	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{adminSub: nil, otherSub: nil, globalSub: {"kiban-superadmin"}},
		map[string]bool{moduleKey: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyID + "/" + adminSub: {isMember: true, active: true},
			companyID + "/" + otherSub: {isMember: true, active: true},
		},
		false,
	)
	seedCompanyAdminFragment(t, pool, moduleKey, companyID, adminSub)

	canBody := func(actorOverride string) map[string]any {
		body := map[string]any{
			"featureKey": "test.feature", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID, "object": map[string]string{"type": "company", "id": companyID},
			"relation": "admin",
		}
		if actorOverride != "" {
			body["actorId"] = actorOverride
		}
		return body
	}

	t.Run("malformed JSON body: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", bytes.NewReader([]byte("{not json")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("actorId in body must match the bearer subject: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody("someone-else-entirely")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("requiresEligibility is refused with 400 (no eligibility source is wired)", func(t *testing.T) {
		for _, path := range []string{"/internal/authz/effective-access/can", "/internal/authz/effective-access/batch-can"} {
			body := canBody("")
			body["requiresEligibility"] = true
			req := httptest.NewRequest(http.MethodPost, path, mustJSON(t, body))
			req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
			rec := httptest.NewRecorder()
			svc.Routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400, body=%s", path, rec.Code, rec.Body.String())
			}
			var out map[string]map[string]any
			decodeBody(t, rec, &out)
			if out["error"]["code"] != errenv.CodeValidationError {
				t.Fatalf("%s: code = %v, want %s", path, out["error"]["code"], errenv.CodeValidationError)
			}
		}
	})

	t.Run("actorId in body matching the bearer subject is accepted (not honored, just not rejected)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody(adminSub)))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("full real allow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody("")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		if body["data"]["allowed"] != true {
			t.Fatalf("data = %+v, want allowed=true", body["data"])
		}
		if body["data"]["reason"] != "ALLOWED" {
			t.Fatalf("reason = %v, want ALLOWED", body["data"]["reason"])
		}
	})

	t.Run("deny is 200 with allowed:false and writes an audit denial row", func(t *testing.T) {
		var before int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied'`, otherSub).Scan(&before); err != nil {
			t.Fatalf("count before: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody("")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, otherSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		if body["data"]["allowed"] != false {
			t.Fatalf("data = %+v, want allowed=false", body["data"])
		}
		if body["data"]["reason"] != "ENGINE_DENIED" {
			t.Fatalf("reason = %v, want ENGINE_DENIED", body["data"]["reason"])
		}

		var after int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied'`, otherSub).Scan(&after); err != nil {
			t.Fatalf("count after: %v", err)
		}
		if after != before+1 {
			t.Fatalf("audit denial rows: before=%d after=%d, want exactly +1", before, after)
		}
	})

	t.Run("dependency unavailable maps to 503 with dependency/step details", func(t *testing.T) {
		// A Service whose Identity client points at an unreachable server: subject lookup fails
		// transport-level, decision.Evaluate collapses to DEPENDENCY_UNAVAILABLE, and writeDecision
		// must map that (and ONLY that) reason to 503.
		unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		unreachable.Close()
		badSvc := *svc
		badSvc.Identity = NewIdentityClient(&http.Client{Timeout: 300 * time.Millisecond}, unreachable.URL)

		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody("")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		badSvc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		if body["error"]["code"] != "AUTHORIZATION_UNAVAILABLE" {
			t.Fatalf("error code = %v, want AUTHORIZATION_UNAVAILABLE", body["error"]["code"])
		}
		details, ok := body["error"]["details"].(map[string]any)
		if !ok || details["dependency"] != "identity" {
			t.Fatalf("error details = %+v, want dependency=identity", body["error"]["details"])
		}
	})

	t.Run("buildDecider error (registry unreachable) maps to 500", func(t *testing.T) {
		badSvc := *svc
		badSvc.KnownEnabled = func(ctx context.Context) (map[string]bool, error) {
			return nil, errFixtureKnownEnabled
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, canBody("")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		badSvc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]string
		decodeBody(t, rec, &body)
		if body["error"]["code"] != "INTERNAL_ERROR" {
			t.Fatalf("error code = %q, want INTERNAL_ERROR", body["error"]["code"])
		}
	})

	t.Run("global scope without requiredPlatformRole is 400 VALIDATION_ERROR", func(t *testing.T) {
		body := map[string]any{"featureKey": "test.global.feature", "moduleKey": moduleKey, "scope": "global"}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, globalSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
		var respBody map[string]map[string]any
		decodeBody(t, rec, &respBody)
		if respBody["error"]["code"] != "VALIDATION_ERROR" {
			t.Fatalf("error = %+v, want VALIDATION_ERROR", respBody["error"])
		}
		if d, _ := respBody["error"]["details"].(map[string]any); d["field"] != "requiredPlatformRole" {
			t.Fatalf("details = %+v, want field=requiredPlatformRole", respBody["error"]["details"])
		}
	})

	t.Run("global scope wire mapping (toDecisionRequest's scope==\"global\" branch)", func(t *testing.T) {
		body := map[string]any{
			"featureKey": "test.global.feature", "moduleKey": moduleKey, "scope": "global",
			"requiredPlatformRole": "kiban-superadmin",
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, globalSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var respBody map[string]map[string]any
		decodeBody(t, rec, &respBody)
		if respBody["data"]["allowed"] != true || respBody["data"]["reason"] != "ALLOWED" {
			t.Fatalf("data = %+v, want allowed=true/ALLOWED for the global-scope superadmin", respBody["data"])
		}
	})
}

var errFixtureKnownEnabled = errors.New("fixture: registry unreachable")

// --- handleBatchCan ---

func TestHandleBatchCan(t *testing.T) {
	const moduleKey, companyID, adminSub = "http-batch-mod", "http-batch-co", "http-batch-admin"

	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{adminSub: nil},
		map[string]bool{moduleKey: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{companyID + "/" + adminSub: {isMember: true, active: true}},
		false,
	)
	seedCompanyAdminFragment(t, pool, moduleKey, companyID, adminSub)

	t.Run("malformed JSON body: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/batch-can", bytes.NewReader([]byte("[")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("actorId mismatch: 400", func(t *testing.T) {
		body := map[string]any{
			"actorId": "not-the-bearer", "moduleKey": moduleKey, "scope": "company", "companyId": companyID,
			"items": []map[string]any{{"object": map[string]string{"type": "company", "id": companyID}, "relation": "admin"}},
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/batch-can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("global scope without requiredPlatformRole is 400 (batch)", func(t *testing.T) {
		body := map[string]any{
			"moduleKey": moduleKey, "scope": "global",
			"items": []map[string]any{{"object": map[string]string{"type": "company", "id": companyID}, "relation": "admin"}},
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/batch-can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "requiredPlatformRole") {
			t.Fatalf("status = %d, want 400 naming requiredPlatformRole, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("more than maxBatchItems items is 400", func(t *testing.T) {
		items := make([]map[string]any, maxBatchItems+1)
		for i := range items {
			items[i] = map[string]any{"object": map[string]string{"type": "company", "id": companyID}, "relation": "admin"}
		}
		body := map[string]any{"moduleKey": moduleKey, "scope": "company", "companyId": companyID, "items": items}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/batch-can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VALIDATION_ERROR") {
			t.Fatalf("status = %d, want 400 VALIDATION_ERROR, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("mixed allow/deny items, each with its own reason; ONE audit row lists the denied items", func(t *testing.T) {
		countRows := func() int {
			var n int
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied'`, adminSub).Scan(&n); err != nil {
				t.Fatalf("count audit rows: %v", err)
			}
			return n
		}
		before := countRows()
		body := map[string]any{
			"featureKey": "batch.feature", "moduleKey": moduleKey, "scope": "company", "companyId": companyID,
			"items": []map[string]any{
				{"object": map[string]string{"type": "company", "id": companyID}, "relation": "admin"},
				{"object": map[string]string{"type": "company", "id": companyID}, "relation": "nonexistent-relation"},
				{"object": map[string]string{"type": "company", "id": "some-other-company"}, "relation": "admin"},
			},
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/batch-can", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body2 map[string][]map[string]any
		decodeBody(t, rec, &body2)
		items := body2["data"]
		if len(items) != 3 {
			t.Fatalf("got %d items, want 3 (body=%s)", len(items), rec.Body.String())
		}
		d0 := items[0]["decision"].(map[string]any)
		if d0["allowed"] != true {
			t.Fatalf("item 0: want allowed=true, got %+v", d0)
		}
		d1 := items[1]["decision"].(map[string]any)
		if d1["allowed"] != false {
			t.Fatalf("item 1: want allowed=false (unknown relation -> engine error -> deny path), got %+v", d1)
		}
		d2 := items[2]["decision"].(map[string]any)
		if d2["allowed"] != false || d2["reason"] != "ENGINE_DENIED" {
			t.Fatalf("item 2: want ENGINE_DENIED (object not bound to the request's company), got %+v", d2)
		}

		if after := countRows(); after != before+1 {
			t.Fatalf("audit denial rows: before=%d after=%d, want exactly +1 for the whole batch", before, after)
		}
		var payload map[string]any
		if err := pool.QueryRow(context.Background(), `SELECT payload FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied' ORDER BY id DESC LIMIT 1`, adminSub).Scan(&payload); err != nil {
			t.Fatalf("read audit payload: %v", err)
		}
		denied, _ := payload["denied"].([]any)
		if payload["featureKey"] != "batch.feature" || payload["deniedCount"] != float64(2) || len(denied) != 2 || payload["truncated"] != false {
			t.Fatalf("audit payload = %+v, want featureKey=batch.feature deniedCount=2 two denied items truncated=false", payload)
		}
	})
}

// --- handleGrants ---

// The grants endpoint is bound to the request's company and gated on the bearer:
// a synthetic module "hg-mod" declares object type "hg_doc" so both object shapes
// (a fragment-declared object and the module's own company_module object) are exercised
// through the REAL endpoint, real engine and real tuple/ledger/audit tables.
const hgFragment = `{"hg_doc": {"company_module": {"this": true}, "owner": {"this": true}, "viewer": {"this": true}}}`

func TestHandleGrants(t *testing.T) {
	const (
		mod        = "hg-mod"
		modOff     = "hg-off"
		adminSub   = "hg-admin"
		memberSub  = "hg-member"
		outsideSub = "hg-outsider"
		superSub   = "hg-super"
	)
	companyID, otherCompany := uuid.NewString(), uuid.NewString()
	anchor := companyID + "/" + mod

	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{adminSub: nil, memberSub: nil, outsideSub: nil, superSub: {summarySuperadminRole}},
		map[string]bool{mod: true, modOff: false},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}, otherCompany: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyID + "/" + adminSub:  {isMember: true, active: true},
			companyID + "/" + memberSub: {isMember: true, active: true},
		},
		false,
	)
	mustExecAuthz(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = $1`, mod)
	mustExecAuthz(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true)`, mod, hgFragment)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, mod)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'hg-%' OR object_id LIKE $1 OR object_id LIKE $2`, companyID+"%", otherCompany+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'hg-%' OR object_id LIKE $1 OR object_id LIKE $2`, companyID+"%", otherCompany+"%")
	})
	grantTestTuple(t, pool, store.Tuple{ObjectType: "company_module", ObjectID: anchor, Relation: "admin", SubjectType: "user", SubjectID: adminSub})
	// hg-doc-other is anchored to ANOTHER company's module; hg-doc-none has no anchor at all.
	grantTestTuple(t, pool, store.Tuple{ObjectType: "hg_doc", ObjectID: "hg-doc-other", Relation: "company_module", SubjectType: "company_module", SubjectID: otherCompany + "/" + mod})

	post := func(t *testing.T, sub string, body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		if _, ok := body["companyId"]; !ok {
			body["companyId"] = companyID
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/grants", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, sub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}
	tuple := func(objType, objID, rel, subjType, subjID string) map[string]string {
		return map[string]string{"objectType": objType, "objectId": objID, "relation": rel, "subjectType": subjType, "subjectId": subjID}
	}
	cmTuple := tuple("company_module", anchor, "viewer", "user", "hg-u1")
	expect := func(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, status, rec.Body.String())
		}
		if code == "" {
			return
		}
		var out map[string]map[string]any
		decodeBody(t, rec, &out)
		if got, _ := out["error"]["code"].(string); got != code {
			t.Fatalf("error code = %q, want %s, body=%s", got, code, rec.Body.String())
		}
	}
	tupleCount := func(t *testing.T, objID string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authz.tuple WHERE object_id = $1`, objID).Scan(&n); err != nil {
			t.Fatalf("count tuples: %v", err)
		}
		return n
	}

	t.Run("malformed JSON body: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/grants", bytes.NewReader([]byte("nope")))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		expect(t, rec, http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("invalid op: 400", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "delete", "tuples": []map[string]string{cmTuple}}), http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("empty tuples: 400", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{}}), http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("missing companyId: 400", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "companyId": "", "tuples": []map[string]string{cmTuple}}), http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("non-UUID companyId: 400", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "companyId": "not-a-uuid", "tuples": []map[string]string{cmTuple}}), http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("base type object (company#admin) is refused: 422", func(t *testing.T) {
		rec := post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("company", companyID, "admin", "user", "hg-u1")}})
		expect(t, rec, http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
		if !strings.Contains(rec.Body.String(), "company") {
			t.Fatalf("message must name the type, body=%s", rec.Body.String())
		}
	})
	t.Run("system#superadmin is refused: 422 (platform-role escalation)", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("system", "platform", "superadmin", "user", adminSub)}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("unknown object type: 422", func(t *testing.T) {
		rec := post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("no_such_type", "x", "viewer", "user", "hg-u1")}})
		expect(t, rec, http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
		if !strings.Contains(rec.Body.String(), "no_such_type") {
			t.Fatalf("message must name the type, body=%s", rec.Body.String())
		}
	})
	t.Run("missing objectType: 422 (was a 500 from the store)", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{{"objectId": "hg-bad", "relation": "admin", "subjectType": "user", "subjectId": "u1"}}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("store validation error (empty subjectId past every rule) maps to 500", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("company_module", anchor, "viewer", "user", "")}}), http.StatusInternalServerError, errenv.CodeInternalError)
	})
	t.Run("company_module object of another company: 422", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("company_module", otherCompany+"/"+mod, "viewer", "user", "hg-u1")}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("company_module object of an unknown module: 422", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("company_module", companyID+"/nope", "viewer", "user", "hg-u1")}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("tuples spanning two modules: 422", func(t *testing.T) {
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{cmTuple, tuple("company_module", companyID+"/"+modOff, "viewer", "user", "hg-u1")}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("module object anchored to another company: 422 on grant and on revoke", func(t *testing.T) {
		for _, op := range []string{"grant", "revoke"} {
			expect(t, post(t, memberSub, map[string]any{"op": op, "tuples": []map[string]string{tuple("hg_doc", "hg-doc-other", "viewer", "user", "hg-u1")}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
		}
	})
	t.Run("module object with no anchor: 422", func(t *testing.T) {
		expect(t, post(t, memberSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("hg_doc", "hg-doc-none", "viewer", "user", "hg-u1")}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("in-request anchor pointing at another company: 422", func(t *testing.T) {
		expect(t, post(t, memberSub, map[string]any{"op": "grant", "tuples": []map[string]string{
			tuple("hg_doc", "hg-doc-x", "owner", "user", memberSub),
			tuple("hg_doc", "hg-doc-x", "company_module", "company_module", otherCompany+"/"+mod),
		}}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
		if tupleCount(t, "hg-doc-x") != 0 {
			t.Fatal("nothing may be written on a refused request")
		}
	})
	t.Run("non-member bearer: 403 COMPANY_MEMBERSHIP_REQUIRED, audited", func(t *testing.T) {
		corr := fmt.Sprintf("hg-outsider-%d", time.Now().UnixNano())
		rec := post(t, outsideSub, map[string]any{"op": "grant", "correlationId": corr, "tuples": []map[string]string{cmTuple}})
		expect(t, rec, http.StatusForbidden, errenv.CodeAuthorizationDenied)
		if !strings.Contains(rec.Body.String(), string(decision.ReasonCompanyMembershipRequired)) {
			t.Fatalf("body must carry the decision reason, body=%s", rec.Body.String())
		}
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied' AND subject = $2`, outsideSub, mod+".grants").Scan(&n); err != nil {
			t.Fatalf("audit query: %v", err)
		}
		if n == 0 {
			t.Fatal("denial must be audited like a /can denial")
		}
	})
	t.Run("module disabled: 403 MODULE_DISABLED", func(t *testing.T) {
		rec := post(t, adminSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("company_module", companyID+"/"+modOff, "viewer", "user", "hg-u1")}})
		expect(t, rec, http.StatusForbidden, errenv.CodeAuthorizationDenied)
		if !strings.Contains(rec.Body.String(), string(decision.ReasonModuleDisabled)) {
			t.Fatalf("body must carry MODULE_DISABLED, body=%s", rec.Body.String())
		}
	})
	t.Run("company_module object without admin: 403 on grant and revoke", func(t *testing.T) {
		for _, op := range []string{"grant", "revoke"} {
			expect(t, post(t, memberSub, map[string]any{"op": op, "tuples": []map[string]string{cmTuple}}), http.StatusForbidden, errenv.CodeAuthorizationDenied)
		}
		if tupleCount(t, anchor) != 1 {
			t.Fatal("only the seeded admin tuple may exist")
		}
	})
	t.Run("company_module object with admin: grant then revoke, audit payload carries companyId/moduleKey", func(t *testing.T) {
		corr := fmt.Sprintf("hg-corr-%d", time.Now().UnixNano())
		expect(t, post(t, adminSub, map[string]any{"op": "grant", "correlationId": corr, "tuples": []map[string]string{cmTuple}}), http.StatusOK, "")
		if tupleCount(t, anchor) != 2 {
			t.Fatalf("tuple count = %d, want 2", tupleCount(t, anchor))
		}
		var payload map[string]any
		if err := pool.QueryRow(context.Background(), `SELECT payload FROM audit.authz__events WHERE actor = $1 AND action = 'authz.grants.grant' AND correlation_id = $2`, adminSub, corr).Scan(&payload); err != nil {
			t.Fatalf("audit row: %v", err)
		}
		if payload["companyId"] != companyID || payload["moduleKey"] != mod || payload["count"] != float64(1) {
			t.Fatalf("audit payload = %v", payload)
		}
		expect(t, post(t, adminSub, map[string]any{"op": "revoke", "tuples": []map[string]string{cmTuple}}), http.StatusOK, "")
		if tupleCount(t, anchor) != 1 {
			t.Fatalf("tuple count after revoke = %d, want 1", tupleCount(t, anchor))
		}
	})
	t.Run("module object with anchor in-request: member (not admin) creates, shares, revokes", func(t *testing.T) {
		expect(t, post(t, memberSub, map[string]any{"op": "grant", "tuples": []map[string]string{
			tuple("hg_doc", "hg-doc-new", "owner", "user", memberSub),
			tuple("hg_doc", "hg-doc-new", "company_module", "company_module", anchor),
		}}), http.StatusOK, "")
		if tupleCount(t, "hg-doc-new") != 2 {
			t.Fatalf("tuple count = %d, want 2", tupleCount(t, "hg-doc-new"))
		}
		expect(t, post(t, memberSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("hg_doc", "hg-doc-new", "viewer", "user", "hg-u2")}}), http.StatusOK, "")
		expect(t, post(t, memberSub, map[string]any{"op": "revoke", "tuples": []map[string]string{tuple("hg_doc", "hg-doc-new", "viewer", "user", "hg-u2")}}), http.StatusOK, "")
		if tupleCount(t, "hg-doc-new") != 2 {
			t.Fatalf("tuple count after revoke = %d, want 2", tupleCount(t, "hg-doc-new"))
		}
	})
	t.Run("platform operator who is not a member passes steps 1-6 (the gateway proxy's actor)", func(t *testing.T) {
		expect(t, post(t, superSub, map[string]any{"op": "grant", "tuples": []map[string]string{tuple("hg_doc", "hg-doc-new", "viewer", "user", "hg-u3")}}), http.StatusOK, "")
	})
}

// TestHandleGrantsSubjectShape is the write-time subject-shape validation proof: a
// non-empty subjectRelation must name a relation actually defined on the subject's type in the
// effective model, checked at grant time (fail-closed 422), so a malformed userset tuple never
// gets written silently unresolvable.
func TestHandleGrantsSubjectShape(t *testing.T) {
	const mod, adminSub = "helpdesk", "http-grant-shape-actor"
	companyID := uuid.NewString()
	anchor := companyID + "/" + mod
	svc, issuer, pool := buildHTTPService(t, map[string][]string{adminSub: nil}, map[string]bool{mod: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{companyID + "/" + adminSub: {isMember: true, active: true}}, false)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, anchor)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id = $1`, anchor)
	})
	grantTestTuple(t, pool, store.Tuple{ObjectType: "company_module", ObjectID: anchor, Relation: "admin", SubjectType: "user", SubjectID: adminSub})
	bearer := "Bearer " + issuer.sign(t, adminSub, time.Now().Add(time.Hour))

	post := func(t *testing.T, tuples []map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/grants", mustJSON(t, map[string]any{"op": "grant", "companyId": companyID, "tuples": tuples}))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}

	t.Run("subjectRelation names an unknown subject type: 422", func(t *testing.T) {
		rec := post(t, []map[string]string{{"objectType": "company_module", "objectId": anchor, "relation": "editor", "subjectType": "not_a_type", "subjectId": "p1", "subjectRelation": "holder"}})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("subjectRelation names a relation not defined on the subject type: 422", func(t *testing.T) {
		rec := post(t, []map[string]string{{"objectType": "company_module", "objectId": anchor, "relation": "editor", "subjectType": "position", "subjectId": "p1", "subjectRelation": "not_a_relation"}})
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid userset subject shape (helpdesk position agent): 200 and the tuple is written", func(t *testing.T) {
		rec := post(t, []map[string]string{{"objectType": "company_module", "objectId": anchor, "relation": "editor", "subjectType": "position", "subjectId": "http-grant-shape-p1", "subjectRelation": "holder"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authz.tuple WHERE object_id=$1 AND subject_relation='holder'`, anchor).Scan(&count); err != nil {
			t.Fatalf("verify tuple: %v", err)
		}
		if count != 1 {
			t.Fatalf("tuple count = %d, want 1", count)
		}
	})

	t.Run("empty subjectRelation (direct subject) skips shape validation: 200", func(t *testing.T) {
		rec := post(t, []map[string]string{{"objectType": "company_module", "objectId": anchor, "relation": "editor", "subjectType": "user", "subjectId": "http-grant-shape-u1"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// --- handleDebugCheck ---

func TestHandleDebugCheck(t *testing.T) {
	const moduleKey, companyID, adminSub = "http-debug-mod", "http-debug-co", "http-debug-admin"

	svcOn, issuer, pool := buildHTTPService(t, map[string][]string{adminSub: nil}, map[string]bool{moduleKey: true}, nil, nil, true)
	seedCompanyAdminFragment(t, pool, moduleKey, companyID, adminSub)
	bearer := "Bearer " + issuer.sign(t, adminSub, time.Now().Add(time.Hour))

	t.Run("wired only when DebugCheck is true: 404 when off", func(t *testing.T) {
		svcOff, issuer2, _ := buildHTTPService(t, map[string][]string{adminSub: nil}, nil, nil, nil, false)
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", mustJSON(t, map[string]any{}))
		req.Header.Set("Authorization", "Bearer "+issuer2.sign(t, adminSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svcOff.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (route must not be registered without DebugCheck)", rec.Code)
		}
	})

	t.Run("requires a bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", mustJSON(t, map[string]any{}))
		rec := httptest.NewRecorder()
		svcOn.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("malformed JSON body: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", bytes.NewReader([]byte("{{{")))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		svcOn.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("allowed check", func(t *testing.T) {
		body := map[string]string{"objectType": "company", "objectId": companyID, "relation": "admin", "subjectType": "user", "subjectId": adminSub}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", mustJSON(t, body))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		svcOn.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]map[string]bool
		decodeBody(t, rec, &out)
		if !out["data"]["allowed"] {
			t.Fatalf("data = %+v, want allowed=true", out["data"])
		}
	})

	t.Run("denied check (unrelated subject)", func(t *testing.T) {
		body := map[string]string{"objectType": "company", "objectId": companyID, "relation": "admin", "subjectType": "user", "subjectId": "nobody-in-particular"}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", mustJSON(t, body))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		svcOn.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]map[string]bool
		decodeBody(t, rec, &out)
		if out["data"]["allowed"] {
			t.Fatalf("data = %+v, want allowed=false", out["data"])
		}
	})

	t.Run("engine CheckError (unknown type) maps to 422", func(t *testing.T) {
		body := map[string]string{"objectType": "no-such-type-anywhere", "objectId": "x", "relation": "y", "subjectType": "user", "subjectId": "z"}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/check", mustJSON(t, body))
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		svcOn.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
		}
		var out map[string]map[string]string
		decodeBody(t, rec, &out)
		if out["error"]["code"] != "VALIDATION_ERROR" {
			t.Fatalf("error code = %q, want VALIDATION_ERROR", out["error"]["code"])
		}
	})
}
