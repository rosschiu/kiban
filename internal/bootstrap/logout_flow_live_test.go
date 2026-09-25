// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
)

// TestLogoutFlow_RoundTrip_LandsOnRootWithoutError: cookie-jar login -> logout -> the final
// landing is the shell root (a real redirect there, not a Keycloak error page) -> the session
// is actually gone (a follow-up silent-auth attempt requires login).
//
// This is browser_login_live_test.go's cookie-jar http.Client approach extended through logout.
// Like that test, it never actually fetches content at redirect_uri/post_logout_redirect_uri —
// it uses the SAME "http://localhost:5173" origin browser_login_live_test.go already
// established as a registered, inspectable-without-fetching redirect target (frontendOrigins()
// also registers the isolated kiban-test stack's own HOST-published gateway TLS origin,
// "https://127.0.0.1:18543", which a real browser login against web/shell/e2e needs — but this
// test doesn't need to fetch content there, so it keeps using the simpler localhost:5173
// target). What this proves is the SHAPE of Keycloak's own response: a real 3xx redirect
// landing exactly on the origin ROOT (`/`, the SDK's default) is only possible if the
// post.logout.redirect.uris client attribute is correctly wired — without it, Keycloak renders
// an inline HTML error page (no redirect at all) instead.
func TestLogoutFlow_RoundTrip_LandsOnRootWithoutError(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()
	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	if err := verifyMFAFlowWiring(ctx, kc); err != nil {
		t.Fatalf("realm browser-flow wiring is not converged before driving the interactive flow: %v (run bootstrap against this stack first)", err)
	}

	// Sanity, checked directly against the realm before driving the flow: kiban-frontend's
	// post.logout.redirect.uris attribute must already be "+" — RealmStep converges this on
	// every bootstrap run (internal/bootstrap/realm.go's reconcileFrontendClient).
	feRep, found, err := kc.findClientByClientID(ctx, frontendClientID)
	if err != nil {
		t.Fatalf("find client %s: %v", frontendClientID, err)
	}
	if !found {
		t.Fatalf("client %s not found (run bootstrap against this stack first)", frontendClientID)
	}
	if got := feRep.Attributes[postLogoutRedirectURIsAttrKey]; got != postLogoutRedirectURIsAttrValue {
		t.Fatalf("%s client's %s attribute = %q, want %q (run bootstrap against this stack first)", frontendClientID, postLogoutRedirectURIsAttrKey, got, postLogoutRedirectURIsAttrValue)
	}

	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}

	username, password := browserLoginTestUser(ctx, t, kc)

	gwBase := "https://127.0.0.1:" + bootstrapTestEnvOrDefault("KIBAN_GATEWAY_TLS_HOST_PORT", "8443")
	redirectURI := "http://localhost:5173/callback"
	// The SDK's postLogoutRedirectUri defaults to the redirectUri's ORIGIN ROOT, not the
	// callback path — mirrored here exactly.
	postLogoutRedirectURI := "http://localhost:5173/"
	verifier := pkceVerifier(t)
	challenge := pkceChallengeS256(verifier)
	state := pkceVerifier(t)[:16]

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// --- 1. login (same interactive flow browser_login_live_test.go proves) ---
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
	formAction, err := extractLoginFormAction(string(loginHTML))
	if err != nil {
		t.Fatalf("could not find the login form's action URL: %v\nbody:\n%s", err, truncate(string(loginHTML), 2000))
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	form := url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
	loginResp, err := client.PostForm(formAction, form)
	if err != nil {
		t.Fatalf("POST login form: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST login form = HTTP %d, want a redirect to %s?code=...", loginResp.StatusCode, redirectURI)
	}
	location := loginResp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", location, err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatalf("final login redirect %q carries no code param", location)
	}

	// --- 2. exchange the code for tokens, exactly as the SDK's exchangeCode() does
	// (web/sdk/src/auth/session.ts) — need the id_token for id_token_hint on logout. ---
	tokenURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", gwBase, deps.KeycloakRealm)
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {frontendClientID},
		"code_verifier": {verifier},
	}
	tokenResp, err := client.PostForm(tokenURL, tokenForm)
	if err != nil {
		t.Fatalf("POST token endpoint: %v", err)
	}
	tokenBody, err := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	if err != nil {
		t.Fatalf("read token response body: %v", err)
	}
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("POST token endpoint = HTTP %d: %s", tokenResp.StatusCode, truncate(string(tokenBody), 2000))
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(tokenBody, &tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("token response missing access_token/id_token: %s", truncate(string(tokenBody), 2000))
	}

	// --- 3. logout: the RP-initiated logout URL the SDK's logout() builds
	// (web/sdk/src/auth/session.ts), driven through the SAME cookie jar the login walked set its
	// Keycloak SSO session cookie into. Stop at the first redirect (like the login POST above) so
	// the Location header — the thing that actually proves the wiring — is inspected directly,
	// without needing anything to actually be listening at postLogoutRedirectURI. ---
	logoutURL := fmt.Sprintf(
		"%s/auth/realms/%s/protocol/openid-connect/logout?%s",
		gwBase, deps.KeycloakRealm,
		url.Values{
			"post_logout_redirect_uri": {postLogoutRedirectURI},
			"client_id":                {frontendClientID},
			"id_token_hint":            {tokens.IDToken},
		}.Encode(),
	)
	logoutResp, err := client.Get(logoutURL)
	if err != nil {
		t.Fatalf("GET logout endpoint: %v", err)
	}
	logoutBody, err := io.ReadAll(logoutResp.Body)
	logoutResp.Body.Close()
	if err != nil {
		t.Fatalf("read logout response body: %v", err)
	}
	// A 3xx redirect landing exactly on postLogoutRedirectURI is the ONLY shape a converged
	// realm produces (SDK default + client attribute). Without the attribute, Keycloak
	// rejects an unregistered post_logout_redirect_uri with an inline 200 HTML error page — no
	// Location header at all — which is exactly the "error marker" landing this proves absent.
	if logoutResp.StatusCode < 300 || logoutResp.StatusCode >= 400 {
		t.Fatalf(
			"logout endpoint returned HTTP %d (want a 3xx redirect to %q) — Keycloak likely rejected post_logout_redirect_uri as unregistered (the realm's logout redirect settings have not converged); body:\n%s",
			logoutResp.StatusCode, postLogoutRedirectURI, truncate(string(logoutBody), 2000),
		)
	}
	gotLocation := logoutResp.Header.Get("Location")
	if gotLocation != postLogoutRedirectURI {
		t.Fatalf("logout redirected to %q, want the shell root %q (the SDK default, not the login callback path)", gotLocation, postLogoutRedirectURI)
	}
	t.Logf("logout round trip landed on %q (HTTP %d, no Keycloak error page)", gotLocation, logoutResp.StatusCode)

	// --- 4. session actually gone: a follow-up silent-auth (prompt=none) attempt through the
	// SAME cookie jar must be refused with login_required — proving Keycloak's SSO session
	// cookie the login step set was actually cleared by logout, not just the SDK's own local
	// tokens. ---
	silentAuthURL := fmt.Sprintf(
		"%s/auth/realms/%s/protocol/openid-connect/auth?%s",
		gwBase, deps.KeycloakRealm,
		url.Values{
			"client_id":             {frontendClientID},
			"redirect_uri":          {redirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {pkceVerifier(t)[:16]},
			"prompt":                {"none"},
		}.Encode(),
	)
	silentResp, err := client.Get(silentAuthURL)
	if err != nil {
		t.Fatalf("GET authorize endpoint (prompt=none): %v", err)
	}
	silentResp.Body.Close()
	if silentResp.StatusCode != http.StatusFound && silentResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("silent-auth attempt after logout = HTTP %d, want a redirect carrying error=login_required", silentResp.StatusCode)
	}
	silentLocation := silentResp.Header.Get("Location")
	silentLocURL, err := url.Parse(silentLocation)
	if err != nil {
		t.Fatalf("parse silent-auth redirect Location %q: %v", silentLocation, err)
	}
	if got := silentLocURL.Query().Get("error"); got != "login_required" {
		t.Fatalf("silent-auth attempt after logout redirected with error=%q, want %q (session should be gone): %s", got, "login_required", silentLocation)
	}
	t.Logf("silent-auth attempt after logout correctly required login (error=%s)", silentLocURL.Query().Get("error"))
}
