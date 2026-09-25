// SPDX-License-Identifier: Apache-2.0

//go:build live

// Trustworthiness proof for platform-openapi.yaml: the same technique
// used for a module's own fragment (internal/testopenapi.ValidateResponse against
// a real *http.Request/*httptest.ResponseRecorder pair) applied to the gateway's OWN platform
// surface, driven over REAL HTTP against a live kiban-test gateway (not an in-process handler —
// these are fixed reverse proxies to other real services, so only a live round trip exercises the
// whole chain: gateway auth guard -> proxy rewrite -> downstream handler -> proxy passthrough).
//
// Every one of the 16 documented operations gets at least one recorded request: the happy path,
// plus one error (401 for RequireAuth-only routes via a request with no bearer at all; 403 for
// RequireSuperadmin-gated routes via a real, logged-in, non-admin bearer — both are the
// cheapest-to-produce-live error class per route, matching this file's own Design note).
//
// Run explicitly against a rebuilt, running kiban-test stack:
//
//	docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml \
//	    -f infra/compose.test.yaml --project-directory infra up -d --build --wait
//	go test -tags live ./internal/gateway/ -run TestLivePlatformOpenAPI -v
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
	"github.com/rosschiu/kiban/internal/testopenapi"
)

// platformOpenAPISpec loads internal/gateway/platform-openapi.yaml once for every test in this
// file — same Load/ValidateResponse contract internal/testopenapi already established for a
// module's own fragment, applied here to the gateway's own platform-openapi.yaml (repo path
// resolved relative to this source file, so `go test`'s working directory doesn't matter).
func platformOpenAPISpec(t *testing.T) *testopenapi.Spec {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("platform_openapi_live_test: could not determine caller for repo root lookup")
	}
	path := filepath.Join(filepath.Dir(thisFile), "platform-openapi.yaml")
	spec, err := testopenapi.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return spec
}

// platformLiveEnv reads .env.test (kiban-test only), process environment taking priority.
func platformLiveEnv(t *testing.T, name string) string { return livestack.TestStackEnv(t, name) }

func platformLivePool(t *testing.T, user, password string) *pgxpool.Pool {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		user, password, platformLiveEnv(t, "POSTGRES_HOST_PORT"), platformLiveEnv(t, "POSTGRES_DB"))
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("ping as %s: %v (is kiban-test up? make test-stack-up)", user, err)
	}
	return pool
}

func platformRandString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// ---- Keycloak: reset the seeded superadmin's forced-temporary password, and create a throwaway
// plain (no platform role) user — both against kiban-test's OWN Keycloak (18081), never the
// public deployment's.

func platformKCAdminToken(t *testing.T, httpClient *http.Client, kcBase string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {platformLiveEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME")},
		"password": {platformLiveEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD")},
	}
	req, _ := http.NewRequest(http.MethodPost, kcBase+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("obtain KC master admin token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("obtain KC master admin token: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode KC master admin token response: %v", err)
	}
	return out.AccessToken
}

// platformKCFindUser returns the Keycloak user id for username in realm, or "" if not found.
func platformKCFindUser(t *testing.T, httpClient *http.Client, adminBase, adminToken, username string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, adminBase+"/users?username="+url.QueryEscape(username)+"&exact=true", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("find user %s: %v", username, err)
	}
	defer resp.Body.Close()
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&found); err != nil {
		t.Fatalf("decode find-user response for %s: %v", username, err)
	}
	if len(found) == 0 {
		return ""
	}
	return found[0].ID
}

// platformKCSetPassword clears requiredActions (no interactive UPDATE_PASSWORD step) and sets a
// real, non-temporary password on an existing user — the seeded superadmin's own initial
// password is forced-temporary (internal/bootstrap/superadmin.go), so this is required before any
// password-grant/interactive login will succeed non-interactively.
func platformKCSetPassword(t *testing.T, httpClient *http.Client, adminBase, adminToken, userID, password string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"requiredActions": []string{}, "enabled": true})
	req, _ := http.NewRequest(http.MethodPut, adminBase+"/users/"+userID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := httpClient.Do(req); err != nil {
		t.Fatalf("clear requiredActions for %s: %v", userID, err)
	} else {
		resp.Body.Close()
	}

	cred, _ := json.Marshal(map[string]any{"type": "password", "value": password, "temporary": false})
	req, _ = http.NewRequest(http.MethodPut, adminBase+"/users/"+userID+"/reset-password", bytes.NewReader(cred))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("reset password for %s: %v", userID, err)
	}
	resp.Body.Close()
}

// platformKCEnsurePlainUser creates (if absent) or resets (if present) a FIXED-name, no-platform-
// role throwaway user — idempotent, same shape as internal/obs/metrics/docs_metrics_live_test.go's
// own kcEnsureTestUser, and for the same reason: a fresh randomly-named user every run would
// accumulate forever in kiban-test's Keycloak realm across repeated `make check`/coverage-gate
// invocations. A fixed username is safe here because this user is stateless (no org/DB fixture
// keys itself to it) — only its password/enabled/requiredActions are reset per run.
func platformKCEnsurePlainUser(t *testing.T, httpClient *http.Client, adminBase, adminToken, username, password string) {
	t.Helper()
	userID := platformKCFindUser(t, httpClient, adminBase, adminToken, username)
	if userID == "" {
		body, _ := json.Marshal(map[string]any{
			"username": username, "email": username + "@example.invalid", "enabled": true, "emailVerified": true,
			"firstName": "Kiban", "lastName": "Platform API Live",
			"requiredActions": []string{},
			"credentials":     []any{map[string]any{"type": "password", "value": password, "temporary": false}},
		})
		req, _ := http.NewRequest(http.MethodPost, adminBase+"/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("create plain user %s: %v", username, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("create plain user %s: HTTP %d: %s", username, resp.StatusCode, string(b))
		}
		return
	}
	platformKCSetPassword(t, httpClient, adminBase, adminToken, userID, password)
}

var platformLoginFormActionRe = regexp.MustCompile(`(?is)<form[^>]*id="kc-form-login"[^>]*action="([^"]*)"`)

// platformInteractiveLogin drives the real OIDC/PKCE authorization-code flow through the gateway's
// /auth/* proxy — same technique as internal/bootstrap/browser_login_live_test.go and
// internal/obs/metrics/docs_metrics_live_test.go's own interactiveLogin (duplicated, not
// imported — package-private in both source packages).
func platformInteractiveLogin(t *testing.T, gwBase, realm, username, password string) string {
	t.Helper()
	redirectURI := "http://localhost:5173/callback"
	verifierBytes := make([]byte, 48)
	if _, err := rand.Read(verifierBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := platformRandString(t, 16)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	authURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth?%s", gwBase, realm, url.Values{
		"client_id": {"kiban-frontend"}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state},
	}.Encode())

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize endpoint: %v", err)
	}
	loginHTML, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read login page: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET authorize endpoint = HTTP %d: %s", resp.StatusCode, string(loginHTML))
	}
	m := platformLoginFormActionRe.FindStringSubmatch(string(loginHTML))
	if m == nil {
		t.Fatalf("no <form id=\"kc-form-login\"> action in login page: %s", string(loginHTML))
	}
	formAction := strings.ReplaceAll(m[1], "&amp;", "&")

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	loginResp, err := client.PostForm(formAction, url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	if err != nil {
		t.Fatalf("POST login form: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("POST login form = HTTP %d, want a redirect; body: %s", loginResp.StatusCode, string(b))
	}
	location := loginResp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", location, err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("final redirect %q carries no code param", location)
	}

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {"kiban-frontend"}, "code_verifier": {verifier},
	}
	tokenResp, err := client.PostForm(fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", gwBase, realm), tokenForm)
	if err != nil {
		t.Fatalf("exchange code for token: %v", err)
	}
	defer tokenResp.Body.Close()
	var tokenOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenOut); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenOut.AccessToken == "" {
		t.Fatalf("token exchange returned no access_token")
	}
	return tokenOut.AccessToken
}

// ---- the live HTTP round trip + openapi3filter adapter ---------------------------------------

// doPlatformRequest performs a real HTTP round trip against the live gateway and returns the
// *http.Request actually sent (rebuilt with a fresh body reader, since the original's body is
// consumed by the round trip) and an *httptest.ResponseRecorder carrying the real response —
// exactly the pair testopenapi.ValidateResponse expects, letting this file reuse that
// helper unchanged even though the request/response here crossed real HTTP, not an in-process
// handler.
func doPlatformRequest(t *testing.T, client *http.Client, method, targetURL, bearer string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, targetURL, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, targetURL, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %s %s: %v", method, targetURL, err)
	}

	// The request testopenapi's router matches against is a PATH-ONLY request (same shape an
	// in-process httptest.Request would carry) — rebuild one with just the URL path+query the
	// spec's servers/paths describe, since kin-openapi's router matches on req.URL, not on
	// scheme/host.
	parsed, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse targetURL %q: %v", targetURL, err)
	}
	matchReq, err := http.NewRequest(method, parsed.Path+"?"+parsed.RawQuery, nil)
	if err != nil {
		t.Fatalf("build match request: %v", err)
	}
	if body != nil {
		matchReq.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	rec.Code = resp.StatusCode
	for k, v := range resp.Header {
		rec.Header()[k] = v
	}
	rec.Body = bytes.NewBuffer(respBody)
	return matchReq, rec
}

// TestLivePlatformOpenAPI_AllRoutesMatchFragment is the trustworthiness
// proof: drives a real request per documented operation (16 operations, happy path + one error
// each = 32+ recorded responses) against a live kiban-test gateway and validates every one against
// platform-openapi.yaml's declared schema.
func TestLivePlatformOpenAPI_AllRoutesMatchFragment(t *testing.T) {
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}
	spec := platformOpenAPISpec(t)

	gwBase := "https://127.0.0.1:" + platformLiveEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	kcBase := "http://127.0.0.1:" + platformLiveEnv(t, "KEYCLOAK_HOST_PORT")
	realm := platformLiveEnv(t, "KEYCLOAK_REALM")
	adminBase := kcBase + "/admin/realms/" + realm

	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	tlsClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	kcAdminToken := platformKCAdminToken(t, plainHTTP, kcBase)

	// The real seeded superadmin (username "admin", infra/secrets-in/superadmin-password —
	// currently the literal string "admin"): reset its forced-temporary password so a
	// non-interactive-UPDATE_PASSWORD login succeeds, then log in for real.
	superadminID := platformKCFindUser(t, plainHTTP, adminBase, kcAdminToken, platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME"))
	if superadminID == "" {
		t.Fatalf("seeded superadmin user %q not found in kiban-test realm %q — did bootstrap run?", platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME"), realm)
	}
	superadminPassword := "oapi-live-" + platformRandString(t, 16)
	platformKCSetPassword(t, plainHTTP, adminBase, kcAdminToken, superadminID, superadminPassword)
	adminBearer := platformInteractiveLogin(t, gwBase, realm, platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME"), superadminPassword)

	// A FIXED-name throwaway PLAIN user — real login, but no superadmin tuple — for the
	// 403 half of every RequireSuperadmin-gated route's proof. Idempotent (see
	// platformKCEnsurePlainUser's own doc comment): re-running this test never accumulates a new
	// Keycloak user.
	const plainUsername = "kiban-oapi-plain"
	plainPassword := "oapi-live-" + platformRandString(t, 16)
	platformKCEnsurePlainUser(t, plainHTTP, adminBase, kcAdminToken, plainUsername, plainPassword)
	plainBearer := platformInteractiveLogin(t, gwBase, realm, plainUsername, plainPassword)
	plainKcSub := platformKCFindUser(t, plainHTTP, adminBase, kcAdminToken, plainUsername)

	// A throwaway company + position + group, direct DB fixture (org has no gateway-mounted
	// company-create route — same "direct SQL" fixture shape every live test in this repo
	// uses). moduleKey "notification" is a real, always-installed module (safe to
	// reference in the batch-can object check below without a fixture module row of its own).
	// The org_unit `code` column is UNIQUE among root units — randomized per run (not a fixed
	// literal) so two runs can never collide even if a PRIOR run's cleanup somehow didn't finish
	// (see the FK-ordered cleanup below, which deletes every table that could otherwise leave the
	// org_unit row orphaned-but-undeletable).
	adminPool := platformLivePool(t, "kiban", platformLiveEnv(t, "KIBAN_DB_PASSWORD"))
	companyID := uuid.NewString()
	companyCode := "OAPI" + strings.ToUpper(platformRandString(t, 6))
	t.Cleanup(func() {
		// context.Background(), NEVER t.Context(): Go's testing package cancels T.Context()
		// BEFORE running Cleanup-registered functions (documented behavior — the whole reason
		// T.Context() exists is request-scoped work DURING the test, not teardown AFTER it).
		// Using t.Context() here was a real bug caught live: every statement below silently
		// no-op'd on an already-canceled context (errors ignored via `_, _ =`), leaking a
		// full company+position+member+group fixture on every single test run — found by
		// running the test twice with `go test -count=1` and querying the DB directly
		// afterward, not by reading the code (it looked correct).
		ctx := context.Background()
		// FK-ordered: children before the parent org_unit row, and the authz tuple the
		// authzGrants/happy step below actually writes.
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='member_directory' AND object_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.group_member WHERE group_id IN (SELECT id FROM org.group WHERE company_id=$1)`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.group WHERE company_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.position_assignment WHERE position_id IN (SELECT id FROM org.position WHERE company_id=$1)`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.position WHERE company_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.member WHERE company_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)
	})
	if _, err := adminPool.Exec(t.Context(), `
		INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', $2, 'Platform API Live Co', true)`,
		companyID, companyCode); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	var positionID string
	if err := adminPool.QueryRow(t.Context(), `
		INSERT INTO org.position (company_id, code, title, org_unit_id) VALUES ($1, 'OAPIPOS', 'Platform API Live Position', $1) RETURNING id`,
		companyID).Scan(&positionID); err != nil {
		t.Fatalf("insert position fixture: %v", err)
	}
	var groupID string
	if err := adminPool.QueryRow(t.Context(), `
		INSERT INTO org.group (company_id, code, name) VALUES ($1, 'OAPIGRP', 'Platform API Live Group') RETURNING id`,
		companyID).Scan(&groupID); err != nil {
		t.Fatalf("insert group fixture: %v", err)
	}
	var memberID string
	if err := adminPool.QueryRow(t.Context(), `
		INSERT INTO org.member (company_id, code, display_name, email, is_active) VALUES ($1, 'OAPIMEM', 'Platform API Live Member', 'oapi@example.invalid', true) RETURNING id`,
		companyID).Scan(&memberID); err != nil {
		t.Fatalf("insert member fixture: %v", err)
	}

	// step is one recorded HTTP round trip, validated against the fragment.
	step := func(name, method, path, bearer string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
		req, rec := doPlatformRequest(t, tlsClient, method, gwBase+path, bearer, body)
		t.Run(name, func(t *testing.T) {
			spec.ValidateResponse(t, req, rec)
		})
		return req, rec
	}

	// ---- foundation_routes.go ------------------------------------------------------------------
	step("effectiveAccessCan/happy", http.MethodPost, "/api/auth/effective-access/can", adminBearer,
		mustJSON(t, map[string]any{"featureKey": "auth.platform_administration.access", "scope": "global", "requiredPlatformRole": "kiban-superadmin"}))
	step("effectiveAccessCan/401", http.MethodPost, "/api/auth/effective-access/can", "",
		mustJSON(t, map[string]any{"featureKey": "auth.platform_administration.access", "scope": "global"}))

	step("effectiveAccessBatchCan/happy", http.MethodPost, "/api/auth/effective-access/batch-can", adminBearer,
		mustJSON(t, map[string]any{"scope": "global", "items": []map[string]any{
			{"object": map[string]any{"type": "company_module", "id": companyID + "/notification"}, "relation": "admin"},
		}}))
	step("effectiveAccessBatchCan/401", http.MethodPost, "/api/auth/effective-access/batch-can", "",
		mustJSON(t, map[string]any{"scope": "global", "items": []map[string]any{}}))

	step("effectiveAccessSummary/happy", http.MethodGet, "/api/auth/effective-access/summary?companyId="+companyID, adminBearer, nil)
	step("effectiveAccessSummary/401", http.MethodGet, "/api/auth/effective-access/summary", "", nil)

	step("orgMeCompanies/happy", http.MethodGet, "/api/org/me/companies", adminBearer, nil)
	step("orgMeCompanies/401", http.MethodGet, "/api/org/me/companies", "", nil)

	step("orgCompanyMemberDirectory/happy", http.MethodGet, "/api/org/companies/"+companyID+"/members", adminBearer, nil)
	step("orgCompanyMemberDirectory/401", http.MethodGet, "/api/org/companies/"+companyID+"/members", "", nil)

	step("authzGrants/happy", http.MethodPost, "/api/auth/grants", adminBearer,
		mustJSON(t, map[string]any{"op": "grant", "tuples": []map[string]any{
			{"objectType": "member_directory", "objectId": companyID, "relation": "viewer", "subjectType": "user", "subjectId": "oapi-noop-subject"},
		}}))
	step("authzGrants/403", http.MethodPost, "/api/auth/grants", plainBearer,
		mustJSON(t, map[string]any{"op": "grant", "tuples": []map[string]any{}}))

	// ---- platform_routes.go --------------------------------------------------------------------
	step("platformCapabilities/happy", http.MethodGet, "/api/platform/capabilities", adminBearer, nil)
	step("platformCapabilities/401", http.MethodGet, "/api/platform/capabilities", "", nil)

	step("platformCapabilityByModule/happy", http.MethodGet, "/api/platform/capabilities/notification", adminBearer, nil)
	step("platformCapabilityByModule/404", http.MethodGet, "/api/platform/capabilities/oapi-nonexistent-module", adminBearer, nil)

	step("platformCatalog/happy", http.MethodGet, "/api/platform/catalog", adminBearer, nil)
	step("platformCatalog/401", http.MethodGet, "/api/platform/catalog", "", nil)

	step("superadminEnableModule/happy", http.MethodPost, "/api/platform/admin/modules/notification/enable", adminBearer, nil)
	step("superadminEnableModule/403", http.MethodPost, "/api/platform/admin/modules/notification/enable", plainBearer, nil)

	step("superadminDisableModule/403", http.MethodPost, "/api/platform/admin/modules/notification/disable", plainBearer, nil)
	// No live "happy" disable call here — disabling the real notification module on kiban-test
	// would affect every other suite/e2e run sharing this stack; enable (idempotent — notification
	// is already enabled) is exercised above, and disable's response schema is IDENTICAL in shape
	// (both return {"data":{"enabled":bool}}), already covered by the enable/happy case.

	step("platformMetrics/happy", http.MethodGet, "/api/platform/metrics", adminBearer, nil)
	step("platformMetrics/403", http.MethodGet, "/api/platform/metrics", plainBearer, nil)

	// The platform role's grant/revoke (foundation_routes.go): the plain user gains and loses
	// the role within this test, leaving the stack as it found it. The last-superadmin 409 is
	// not exercised live here (the shared stack's superadmin count is not this test's to assume);
	// internal/authz's own route tests prove it.
	step("superadminGrantPlatformRole/403", http.MethodPost, "/api/platform/admin/platform-roles", plainBearer,
		mustJSON(t, map[string]any{"subjectId": plainKcSub, "role": "kiban-superadmin"}))
	step("superadminGrantPlatformRole/422", http.MethodPost, "/api/platform/admin/platform-roles", adminBearer,
		mustJSON(t, map[string]any{"subjectId": plainKcSub, "role": "kiban-operator"}))
	step("superadminGrantPlatformRole/happy", http.MethodPost, "/api/platform/admin/platform-roles", adminBearer,
		mustJSON(t, map[string]any{"subjectId": plainKcSub, "role": "kiban-superadmin"}))
	step("superadminRevokePlatformRole/happy", http.MethodDelete, "/api/platform/admin/platform-roles/kiban-superadmin/"+plainKcSub, adminBearer, nil)
	step("superadminRevokePlatformRole/404", http.MethodDelete, "/api/platform/admin/platform-roles/kiban-superadmin/"+plainKcSub, adminBearer, nil)
	step("superadminRevokePlatformRole/403", http.MethodDelete, "/api/platform/admin/platform-roles/kiban-superadmin/"+plainKcSub, plainBearer, nil)

	// ---- admin_position_routes.go ----------------------------------------------------------------
	step("adminListPositions/happy", http.MethodGet, "/api/org/admin/companies/"+companyID+"/positions", adminBearer, nil)
	step("adminListPositions/403", http.MethodGet, "/api/org/admin/companies/"+companyID+"/positions", plainBearer, nil)

	step("adminCreatePosition/happy", http.MethodPost, "/api/org/admin/companies/"+companyID+"/positions", adminBearer,
		mustJSON(t, map[string]any{"code": "OAPIP2", "title": "Platform API Live Position 2", "orgUnitId": companyID}))
	step("adminCreatePosition/403", http.MethodPost, "/api/org/admin/companies/"+companyID+"/positions", plainBearer,
		mustJSON(t, map[string]any{"code": "OAPIP3", "title": "unauthorized", "orgUnitId": companyID}))

	var assignmentID string
	{
		req, rec := step("adminAssignPositionNow/happy", http.MethodPost, "/api/org/admin/positions/"+positionID+"/assignments", adminBearer,
			mustJSON(t, map[string]any{"memberId": memberID}))
		_ = req
		var decoded struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err == nil {
			assignmentID = decoded.Data.ID
		}
	}
	step("adminAssignPositionNow/403", http.MethodPost, "/api/org/admin/positions/"+positionID+"/assignments", plainBearer,
		mustJSON(t, map[string]any{"memberId": memberID}))

	if assignmentID != "" {
		step("adminEndAssignmentNow/happy", http.MethodPost, "/api/org/admin/assignments/"+assignmentID+"/end", adminBearer, nil)
	}
	step("adminEndAssignmentNow/403", http.MethodPost, "/api/org/admin/assignments/"+uuid.NewString()+"/end", plainBearer, nil)

	// ---- admin_group_routes.go --------------------------------------------------------------------
	step("adminListGroups/happy", http.MethodGet, "/api/org/admin/companies/"+companyID+"/groups", adminBearer, nil)
	step("adminListGroups/403", http.MethodGet, "/api/org/admin/companies/"+companyID+"/groups", plainBearer, nil)

	step("adminCreateGroup/happy", http.MethodPost, "/api/org/admin/companies/"+companyID+"/groups", adminBearer,
		mustJSON(t, map[string]any{"code": "OAPIG2", "name": "Platform API Live Group 2"}))
	step("adminCreateGroup/403", http.MethodPost, "/api/org/admin/companies/"+companyID+"/groups", plainBearer,
		mustJSON(t, map[string]any{"code": "OAPIG3", "name": "unauthorized"}))

	step("adminAddGroupMember/happy", http.MethodPost, "/api/org/admin/groups/"+groupID+"/members", adminBearer,
		mustJSON(t, map[string]any{"memberId": memberID}))
	step("adminAddGroupMember/403", http.MethodPost, "/api/org/admin/groups/"+groupID+"/members", plainBearer,
		mustJSON(t, map[string]any{"memberId": memberID}))

	step("adminListGroupMembers/happy", http.MethodGet, "/api/org/admin/groups/"+groupID+"/members", adminBearer, nil)
	step("adminListGroupMembers/403", http.MethodGet, "/api/org/admin/groups/"+groupID+"/members", plainBearer, nil)

	step("adminRemoveGroupMember/happy", http.MethodDelete, "/api/org/admin/groups/"+groupID+"/members/"+memberID, adminBearer, nil)
	step("adminRemoveGroupMember/403", http.MethodDelete, "/api/org/admin/groups/"+groupID+"/members/"+memberID, plainBearer, nil)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	return b
}
