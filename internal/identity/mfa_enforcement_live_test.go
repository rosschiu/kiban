// SPDX-License-Identifier: Apache-2.0

//go:build live

package identity

import (
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
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Prove that setting an MFA policy in Kiban demonstrably changes what a real Keycloak login
// demands. TestLive_MfaSyncVisibleInKeycloak only proves the required_mode attribute is
// VISIBLE via the admin API; it never drives an actual login. These three tests drive the REAL
// interactive Keycloak login form through a cookie-jar http.Client — the same technique as
// internal/bootstrap/browser_login_live_test.go's TestBrowserLogin_InteractiveFlowIssuesAuthorizationCode
// — against the gateway's TLS origin and the bootstrap-converged "kiban-frontend" client
// (internal/bootstrap/realm.go's frontendClientID; realm-kiban.json's static import-time seed
// of the same client lacks the gateway's redirect URI until bootstrap has reconciled it).
//
// Run against an isolated test stack only (internal/livestack's guard refuses DB-touching test
// helpers when infra/.public-mode is present).

const (
	mfaEnforcementClientID    = "kiban-frontend"
	mfaEnforcementRedirectURI = "http://localhost:5173/callback"
)

// mfaEnforcementGatewayBase resolves the gateway's TLS origin from KIBAN_GATEWAY_TLS_HOST_PORT
// (default 8443, `make dev`/`make public-up`'s own port) — `make test-stack-up`'s
// .env.test sets this to the isolated stack's own remapped port, same as
// internal/bootstrap/browser_login_live_test.go.
func mfaEnforcementGatewayBase() string {
	if v := os.Getenv("KIBAN_GATEWAY_TLS_HOST_PORT"); v != "" {
		return "https://127.0.0.1:" + v
	}
	return "https://127.0.0.1:8443"
}

// mfaEnforcementLoginFormActionRe / mfaEnforcementActionAttrRe mirror
// internal/bootstrap/browser_login_live_test.go's extractLoginFormAction technique, duplicated
// here (unexported, package-local) rather than imported across packages.
var mfaEnforcementLoginFormActionRe = regexp.MustCompile(`(?is)<form[^>]*id="kc-form-login"[^>]*>`)
var mfaEnforcementActionAttrRe = regexp.MustCompile(`(?is)action="([^"]*)"`)

// mfaEnforcementTOTPSetupMarkerRe matches Keycloak's built-in TOTP-setup page (template
// login-config-totp.ftl in Keycloak 26.x renders a form with this id) — the "challenge/setup
// page instead of the redirect" marker these tests assert on, not just a 200. If a future
// Keycloak upgrade changes this marker, this regex (and ONLY this regex) needs updating — the
// enforcement logic itself does not depend on it.
var mfaEnforcementTOTPSetupMarkerRe = regexp.MustCompile(`(?is)id="kc-totp-settings-form"`)

func mfaEnforcementCookieJarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		// The gateway terminates TLS with a self-signed dev cert — InsecureSkipVerify is scoped
		// to this throwaway client only.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func mfaEnforcementPKCEVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func mfaEnforcementPKCEChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mfaEnforcementExtractLoginFormAction is extractLoginFormAction's technique, package-local.
func mfaEnforcementExtractLoginFormAction(html string) (string, error) {
	tag := mfaEnforcementLoginFormActionRe.FindString(html)
	if tag == "" {
		return "", fmt.Errorf("no <form id=\"kc-form-login\"> found")
	}
	m := mfaEnforcementActionAttrRe.FindStringSubmatch(tag)
	if m == nil {
		return "", fmt.Errorf("login form tag has no action attribute: %s", tag)
	}
	return strings.ReplaceAll(m[1], "&amp;", "&"), nil
}

func mfaEnforcementTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}

// mfaEnforcementLoginAttempt drives one full GET-authorize + POST-credentials round trip with a
// fresh cookie jar and PKCE pair, returning the final HTTP response (redirect on success,
// required-action page on a pending setup) and its body — the caller asserts on whichever it
// expects.
func mfaEnforcementLoginAttempt(t *testing.T, cfg kcConfig, username, password string) (status int, location string, body string) {
	t.Helper()
	client := mfaEnforcementCookieJarClient(t)
	verifier := mfaEnforcementPKCEVerifier(t)
	challenge := mfaEnforcementPKCEChallengeS256(verifier)
	state := mfaEnforcementPKCEVerifier(t)[:16]

	authURL := fmt.Sprintf(
		"%s/auth/realms/%s/protocol/openid-connect/auth?%s",
		mfaEnforcementGatewayBase(), cfg.realm,
		url.Values{
			"client_id":             {mfaEnforcementClientID},
			"redirect_uri":          {mfaEnforcementRedirectURI},
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
		t.Fatalf("GET authorize endpoint = HTTP %d, want 200 (login page); body:\n%s", resp.StatusCode, mfaEnforcementTruncate(string(loginHTML), 2000))
	}

	formAction, err := mfaEnforcementExtractLoginFormAction(string(loginHTML))
	if err != nil {
		t.Fatalf("could not find login form action: %v\nbody:\n%s", err, mfaEnforcementTruncate(string(loginHTML), 2000))
	}

	form := url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
	loginResp, err := client.PostForm(formAction, form)
	if err != nil {
		t.Fatalf("POST login form: %v", err)
	}
	respBody, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if err != nil {
		t.Fatalf("read login response body: %v", err)
	}

	// Keycloak 26 delivers pending required actions via a 302 to its own
	// login-actions/required-action page, not inline in the credential POST's response — follow
	// exactly that one hop (and only that one: a redirect to the client's redirect_uri is the
	// SUCCESS shape the callers assert on as a redirect, and must be returned raw).
	if loc := loginResp.Header.Get("Location"); (loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusSeeOther) &&
		strings.Contains(loc, "login-actions/required-action") {
		actionResp, err := client.Get(loc)
		if err != nil {
			t.Fatalf("GET required-action page: %v", err)
		}
		defer actionResp.Body.Close()
		actionBody, err := io.ReadAll(actionResp.Body)
		if err != nil {
			t.Fatalf("read required-action page body: %v", err)
		}
		return actionResp.StatusCode, actionResp.Header.Get("Location"), string(actionBody)
	}

	return loginResp.StatusCode, loginResp.Header.Get("Location"), string(respBody)
}

// mfaEnforcementKCUser is the minimal Keycloak user representation these tests create/reset.
type mfaEnforcementKCUser struct {
	ID       string
	Username string
	Password string
}

// mfaEnforcementEnsureTestUser creates (or resets) a throwaway Keycloak user with a real,
// non-temporary password and no requiredActions — mirrors
// internal/bootstrap/browser_login_live_test.go's browserLoginTestUser precedent, duplicated
// here via AdminClient's own (app-realm service-account) bearer rather than a master-realm
// client, since this package's AdminClient never uses master-realm credentials.
func mfaEnforcementEnsureTestUser(ctx context.Context, t *testing.T, admin *AdminClient, cfg kcConfig, username string) mfaEnforcementKCUser {
	t.Helper()
	password := "mfa-enforce-" + mfaEnforcementPKCEVerifier(t)[:20]

	token, err := admin.token(ctx)
	if err != nil {
		t.Fatalf("fetch admin token: %v", err)
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}

	// Find by username (exact match).
	findURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true", cfg.baseURL, cfg.realm, url.QueryEscape(username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, findURL, nil)
	if err != nil {
		t.Fatalf("build find-user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("find test user: %v", err)
	}
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&found); err != nil {
		resp.Body.Close()
		t.Fatalf("decode find-user response: %v", err)
	}
	resp.Body.Close()

	if len(found) == 0 {
		createBody, _ := json.Marshal(map[string]any{
			"username":        username,
			"email":           username + "@example.invalid",
			"enabled":         true,
			"emailVerified":   true,
			"firstName":       "Kiban",
			"lastName":        "MFA Enforcement",
			"requiredActions": []string{},
			"credentials":     []map[string]any{{"type": "password", "value": password, "temporary": false}},
		})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/admin/realms/%s/users", cfg.baseURL, cfg.realm), strings.NewReader(string(createBody)))
		if err != nil {
			t.Fatalf("build create-user request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err = httpClient.Do(req)
		if err != nil {
			t.Fatalf("create test user: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("create test user: status %d, body: %s", resp.StatusCode, mfaEnforcementTruncate(string(body), 1000))
		}
		loc := resp.Header.Get("Location")
		parts := strings.Split(loc, "/")
		return mfaEnforcementKCUser{ID: parts[len(parts)-1], Username: username, Password: password}
	}

	id := found[0].ID
	// Reset requiredActions/enabled + password on every run — a prior run (or another test in
	// this file) may have left the account requiring TOTP/passkey setup.
	resetBody, _ := json.Marshal(map[string]any{"requiredActions": []string{}, "enabled": true})
	req, err = http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/admin/realms/%s/users/%s", cfg.baseURL, cfg.realm, id), strings.NewReader(string(resetBody)))
	if err != nil {
		t.Fatalf("build reset-user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := httpClient.Do(req); err != nil {
		t.Fatalf("reset test user requiredActions: %v", err)
	} else {
		resp.Body.Close()
	}

	pwBody, _ := json.Marshal(map[string]any{"type": "password", "value": password, "temporary": false})
	req, err = http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", cfg.baseURL, cfg.realm, id), strings.NewReader(string(pwBody)))
	if err != nil {
		t.Fatalf("build reset-password request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := httpClient.Do(req); err != nil {
		t.Fatalf("reset test user password: %v", err)
	} else {
		resp.Body.Close()
	}

	// Also clear any stored TOTP credential from a prior run of the required-otp test, so a
	// re-run starts from the same "no runtime MFA credential" state.
	credsURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/credentials", cfg.baseURL, cfg.realm, id)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, credsURL, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+token)
		if resp, err := httpClient.Do(req); err == nil {
			var creds []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&creds)
			resp.Body.Close()
			for _, c := range creds {
				if c.Type == "otp" {
					delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete, credsURL+"/"+c.ID, nil)
					delReq.Header.Set("Authorization", "Bearer "+token)
					if delResp, err := httpClient.Do(delReq); err == nil {
						delResp.Body.Close()
					}
				}
			}
		}
	}

	return mfaEnforcementKCUser{ID: id, Username: username, Password: password}
}

// TestLive_MfaEnforcement_NoPolicyAllowsPlainLogin is the regression guard: with no MFA policy
// override (and the seeded global policy's required=false), a plain password login succeeds —
// the SAME login flow the next two tests exercise, proving this suite isn't just checking the
// failure path.
func TestLive_MfaEnforcement_NoPolicyAllowsPlainLogin(t *testing.T) {
	cfg := loadKCConfig(t)
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	kcUser := mfaEnforcementEnsureTestUser(ctx, t, adminClient, cfg, "kiban-mfa-enforce-nopolicy")

	user, err := store.ResolveOrCreate(ctx, kcUser.ID, kcUser.Username+"@example.invalid", kcUser.Username)
	if err != nil {
		t.Fatalf("resolve-or-create: %v", err)
	}
	if err := store.ClearUserPolicy(ctx, user.ID, nil); err != nil {
		t.Fatalf("clear user policy: %v", err)
	}
	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync mfa policy: %v", err)
	}
	for _, o := range outcomes {
		if o.KcSub == kcUser.ID && !o.Success {
			t.Fatalf("sync failed for test user: %s", o.Error)
		}
	}

	status, location, body := mfaEnforcementLoginAttempt(t, cfg, kcUser.Username, kcUser.Password)
	if status != http.StatusFound && status != http.StatusSeeOther {
		t.Fatalf("no-policy login = HTTP %d, want a redirect (302/303) to %s?code=...; body:\n%s", status, mfaEnforcementRedirectURI, mfaEnforcementTruncate(body, 2000))
	}
	if !strings.HasPrefix(location, mfaEnforcementRedirectURI) {
		t.Fatalf("no-policy login redirect Location = %q, want prefix %q", location, mfaEnforcementRedirectURI)
	}
}

// TestLive_MfaEnforcement_RequiredOtpPolicyChallengesLogin is the core enforcement proof:
// syncing a required-otp policy for a fixture user makes the SAME login flow return
// Keycloak's TOTP-setup page instead of the redirect — asserted on the page's own form marker,
// not just a non-redirect status.
func TestLive_MfaEnforcement_RequiredOtpPolicyChallengesLogin(t *testing.T) {
	cfg := loadKCConfig(t)
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	kcUser := mfaEnforcementEnsureTestUser(ctx, t, adminClient, cfg, "kiban-mfa-enforce-required")

	user, err := store.ResolveOrCreate(ctx, kcUser.ID, kcUser.Username+"@example.invalid", kcUser.Username)
	if err != nil {
		t.Fatalf("resolve-or-create: %v", err)
	}
	if err := store.SetUserPolicy(ctx, user.ID, true, "otp", nil); err != nil {
		t.Fatalf("set user policy: %v", err)
	}
	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync mfa policy: %v", err)
	}
	for _, o := range outcomes {
		if o.KcSub == kcUser.ID {
			if !o.Success {
				t.Fatalf("sync failed for test user: %s", o.Error)
			}
			if o.RequiredMode != "otp_required" {
				t.Fatalf("sync outcome required_mode = %q, want %q", o.RequiredMode, "otp_required")
			}
		}
	}

	status, _, body := mfaEnforcementLoginAttempt(t, cfg, kcUser.Username, kcUser.Password)
	if status == http.StatusFound || status == http.StatusSeeOther {
		t.Fatalf("required-otp login = HTTP %d (redirect), want the TOTP-setup page (200) — the policy did not challenge the login; body:\n%s", status, mfaEnforcementTruncate(body, 2000))
	}
	if !mfaEnforcementTOTPSetupMarkerRe.MatchString(body) {
		t.Fatalf("required-otp login response has no TOTP-setup page marker (id=\"kc-totp-settings-form\"); status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
	}
}

// TestLive_MfaEnforcement_PolicyRemovedRestoresPlainLogin: clearing a
// user's required-otp override and re-syncing (required_mode -> "none") restores plain password
// login for that SAME user — proves the enforcement is policy-driven, not a one-way ratchet.
func TestLive_MfaEnforcement_PolicyRemovedRestoresPlainLogin(t *testing.T) {
	cfg := loadKCConfig(t)
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	kcUser := mfaEnforcementEnsureTestUser(ctx, t, adminClient, cfg, "kiban-mfa-enforce-removed")

	user, err := store.ResolveOrCreate(ctx, kcUser.ID, kcUser.Username+"@example.invalid", kcUser.Username)
	if err != nil {
		t.Fatalf("resolve-or-create: %v", err)
	}

	// Start required, prove it challenges (same technique as the previous test, abbreviated), then clear.
	if err := store.SetUserPolicy(ctx, user.ID, true, "otp", nil); err != nil {
		t.Fatalf("set user policy: %v", err)
	}
	if _, err := store.SyncMfaPolicy(ctx, adminClient); err != nil {
		t.Fatalf("sync mfa policy (required): %v", err)
	}
	status, _, body := mfaEnforcementLoginAttempt(t, cfg, kcUser.Username, kcUser.Password)
	if status == http.StatusFound || status == http.StatusSeeOther {
		t.Fatalf("precondition failed: required-otp login = HTTP %d (redirect), want the TOTP-setup page before testing removal; body:\n%s", status, mfaEnforcementTruncate(body, 2000))
	}

	if err := store.ClearUserPolicy(ctx, user.ID, nil); err != nil {
		t.Fatalf("clear user policy: %v", err)
	}
	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync mfa policy (cleared): %v", err)
	}
	for _, o := range outcomes {
		if o.KcSub == kcUser.ID {
			if !o.Success {
				t.Fatalf("sync failed for test user: %s", o.Error)
			}
			if o.RequiredMode != "none" {
				t.Fatalf("sync outcome required_mode after clear = %q, want %q", o.RequiredMode, "none")
			}
		}
	}

	// Requires a fresh Keycloak user reset: the earlier failed attempt may have left a
	// transient auth-session required action queued, but a brand new login attempt (fresh
	// cookie jar, fresh auth session) re-evaluates the authenticator from scratch — no reset
	// needed beyond the policy re-sync above.
	status, location, body := mfaEnforcementLoginAttempt(t, cfg, kcUser.Username, kcUser.Password)
	if status != http.StatusFound && status != http.StatusSeeOther {
		t.Fatalf("policy-removed login = HTTP %d, want a redirect (302/303) to %s?code=...; body:\n%s", status, mfaEnforcementRedirectURI, mfaEnforcementTruncate(body, 2000))
	}
	if !strings.HasPrefix(location, mfaEnforcementRedirectURI) {
		t.Fatalf("policy-removed login redirect Location = %q, want prefix %q", location, mfaEnforcementRedirectURI)
	}
}
