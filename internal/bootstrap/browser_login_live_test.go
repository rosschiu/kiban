// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
)

// TestBrowserLogin_InteractiveFlowIssuesAuthorizationCode is the permanent regression gate for
// the browser-flow structure. It drives the REAL interactive OIDC/PKCE authorization-code flow
// through the TLS gateway's /auth/* proxy against the live realm, exactly the round trip
// web/sdk/e2e/login.spec.ts drives with a real browser (Playwright is not this package's tool;
// a cookie-jar http.Client walking the same Keycloak login form is the Go-native equivalent) —
// with a broken flow layout this fails on the very first GET, with Keycloak's login page
// rendering "Invalid username or password" before any credentials were ever submitted. This
// test proves a throwaway user with a real (non-temporary) password and no MFA-setup requirement
// reaches the login form, submits valid credentials, and the flow completes with an
// authorization `code` on the final redirect to redirect_uri.
func TestBrowserLogin_InteractiveFlowIssuesAuthorizationCode(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()
	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	// Sanity: the realm's browser flow structure must already be correct (RealmStep's own
	// verifyMFAFlowWiring, exercised directly here too so a failure at THIS assertion points
	// straight at the structural check rather than an opaque HTTP-parsing failure below).
	if err := verifyMFAFlowWiring(ctx, kc); err != nil {
		t.Fatalf("realm browser-flow wiring is not converged before driving the interactive flow: %v (run `make dev-clean && make dev` first)", err)
	}

	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}

	username, password := browserLoginTestUser(ctx, t, kc)

	// KIBAN_GATEWAY_TLS_HOST_PORT lets the isolated test stack (.env.test,
	// `make test-stack-up`) point this live browser-flow proof at ITS OWN gateway instead of the
	// one `make dev`/`make public-up` may have running on the default 8443 — see
	// bootstrapTestEnvOrDefault's own comment.
	gwBase := "https://127.0.0.1:" + bootstrapTestEnvOrDefault("KIBAN_GATEWAY_TLS_HOST_PORT", "8443")
	redirectURI := "http://localhost:5173/callback"
	verifier := pkceVerifier(t)
	challenge := pkceChallengeS256(verifier)
	state := pkceVerifier(t)[:16]

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	// The gateway terminates TLS with a self-signed dev cert (infra/e2e-login.sh's own `curl
	// -sk` precedent) — InsecureSkipVerify is scoped to this throwaway client only.
	client := &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	authURL := fmt.Sprintf(
		"%s/auth/realms/%s/protocol/openid-connect/auth?%s",
		gwBase, deps.KeycloakRealm,
		url.Values{
			"client_id":             {frontendClientID},
			"redirect_uri":          {redirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {state},
		}.Encode(),
	)

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize endpoint: %v", err)
	}
	loginHTML, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read login page body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET authorize endpoint = HTTP %d, want 200 (login page) — body:\n%s", resp.StatusCode, truncate(string(loginHTML), 2000))
	}
	if strings.Contains(string(loginHTML), "Invalid username or password") {
		t.Fatalf("login page already shows \"Invalid username or password\" before any credentials were submitted — this is exactly the flow-ordering defect (REQUIRED kiban-local-mfa-setup evaluated before any user is set); body:\n%s", truncate(string(loginHTML), 2000))
	}

	formAction, err := extractLoginFormAction(string(loginHTML))
	if err != nil {
		t.Fatalf("could not find the login form's action URL in the login page: %v\nbody:\n%s", err, truncate(string(loginHTML), 2000))
	}

	// Submit credentials. CheckRedirect stops at the first redirect so the Location header (the
	// authorization code, on success) can be inspected directly rather than followed into a
	// redirect_uri nothing is listening on.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	form := url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
	loginResp, err := client.PostForm(formAction, form)
	if err != nil {
		t.Fatalf("POST login form: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("POST login form = HTTP %d, want a redirect (302/303) to %s?code=...; body:\n%s", loginResp.StatusCode, redirectURI, truncate(string(body), 2000))
	}

	location := loginResp.Header.Get("Location")
	if location == "" {
		t.Fatal("POST login form redirected with no Location header")
	}
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", location, err)
	}
	if !strings.HasPrefix(location, redirectURI) {
		t.Fatalf("redirect Location = %q, want it to start with redirect_uri %q (the flow did not complete against our client)", location, redirectURI)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("final redirect %q carries no `code` param — the interactive browser flow did not reach a successful authorization (params: %v)", location, locURL.Query())
	}
	if got := locURL.Query().Get("state"); got != state {
		t.Fatalf("final redirect state = %q, want %q", got, state)
	}
	t.Logf("interactive browser flow issued authorization code (len=%d) for user %q", len(code), username)
}

// browserLoginTestUser creates (or resets) a throwaway Keycloak user with a real, non-temporary
// password and no requiredActions/MFA-setup attributes (mirrors infra/e2e-login.sh step 7's
// "regular_username" fixture precedent) — idempotent create-or-reuse so re-running this test
// against the same stack never fails on a duplicate-user conflict.
func browserLoginTestUser(ctx context.Context, t *testing.T, kc *kcMasterClient) (username, password string) {
	t.Helper()
	username = "kiban-browser-login"
	password = "browser-login-" + pkceVerifier(t)[:20]

	existing, found, err := kc.findUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("find test user: %v", err)
	}
	if !found {
		rep := kcUserRep{
			Username: username, Email: username + "@example.invalid", Enabled: true, EmailVerified: true,
			FirstName: "Kiban", LastName: "Browser Login",
			RequiredActions: []string{},
			Credentials:     []kcCredentialRep{{Type: "password", Value: password, Temporary: false}},
		}
		if _, err := kc.doCreate(ctx, "/users", rep); err != nil {
			t.Fatalf("create test user: %v", err)
		}
		return username, password
	}

	// Reset requiredActions + password on every run — a prior run (or a manual poke) may have
	// left the account in a state this test can't drive interactively.
	if _, err := kc.do(ctx, http.MethodPut, "/users/"+existing.ID, map[string]any{"requiredActions": []string{}, "enabled": true}, nil); err != nil {
		t.Fatalf("reset test user requiredActions: %v", err)
	}
	if _, err := kc.do(ctx, http.MethodPut, "/users/"+existing.ID+"/reset-password", kcCredentialRep{Type: "password", Value: password, Temporary: false}, nil); err != nil {
		t.Fatalf("reset test user password: %v", err)
	}
	return username, password
}

func pkceVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var loginFormTagRe = regexp.MustCompile(`(?is)<form[^>]*id="kc-form-login"[^>]*>`)
var actionAttrRe = regexp.MustCompile(`(?is)action="([^"]*)"`)

// extractLoginFormAction finds Keycloak's login form (id="kc-form-login") and pulls its action
// URL, which carries the session/execution/tab_id params Keycloak's flow engine needs to match
// this POST back to the GET that rendered the page — hand-rolled, not html/template, since this
// is a read of Keycloak-generated markup, not a template this repo owns.
func extractLoginFormAction(html string) (string, error) {
	tag := loginFormTagRe.FindString(html)
	if tag == "" {
		return "", fmt.Errorf("no <form id=\"kc-form-login\"> found")
	}
	m := actionAttrRe.FindStringSubmatch(tag)
	if m == nil {
		return "", fmt.Errorf("login form tag has no action attribute: %s", tag)
	}
	// Keycloak escapes `&` as `&amp;` in the HTML attribute.
	return strings.ReplaceAll(m[1], "&amp;", "&"), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}
