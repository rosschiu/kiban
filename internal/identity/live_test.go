// SPDX-License-Identifier: Apache-2.0

//go:build live

// Live proofs exercised against the REAL `make dev` stack (real Postgres, real Keycloak with
// the kiban-authenticator provider baked in and the kiban-identity-service service-account
// client). Build-tag-fenced out of `make check`/`make test` — run explicitly with
// `go test -tags live ./internal/identity/ -run TestLive -v`.
package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fetchMasterAdminToken gets a password-grant token for the bootstrap admin against the master
// realm — used ONLY by this live test to call the admin REST API's read-only
// authenticator-providers listing (never used by the identity service itself: master-realm
// credentials are barred from the runtime service).
func fetchMasterAdminToken(t *testing.T, cfg kcConfig) string {
	t.Helper()
	form := url.Values{
		"client_id":  {"admin-cli"},
		"username":   {testEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME")},
		"password":   {testEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD")},
		"grant_type": {"password"},
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(
		cfg.baseURL+"/realms/master/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("fetch master admin token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch master admin token: status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(resp, &body); err != nil {
		t.Fatalf("decode master admin token response: %v", err)
	}
	return body.AccessToken
}

func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

// kcConfig reads the live Keycloak connection details this test needs, failing loudly if any
// are missing rather than silently skipping (an unrun live check must never be reported as
// passed).
type kcConfig struct {
	baseURL      string
	realm        string
	clientSecret string
}

func loadKCConfig(t *testing.T) kcConfig {
	t.Helper()
	return kcConfig{
		baseURL:      "http://127.0.0.1:" + testEnv(t, "KEYCLOAK_HOST_PORT"),
		realm:        testEnv(t, "KEYCLOAK_REALM"),
		clientSecret: testEnv(t, "KEYCLOAK_IDENTITY_CLIENT_SECRET"),
	}
}

// TestLive_ProviderRegistered proves the kiban-authenticator provider is
// registered in the running Keycloak — proven via the admin REST API's authenticator-providers
// listing rather than grepping container logs (equally authoritative, no docker exec needed).
func TestLive_ProviderRegistered(t *testing.T) {
	cfg := loadKCConfig(t)
	adminBearer := fetchMasterAdminToken(t, cfg)

	req, err := http.NewRequest(http.MethodGet, cfg.baseURL+"/admin/realms/"+cfg.realm+"/authentication/authenticator-providers", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminBearer)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("list authenticator providers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list authenticator providers: status %d", resp.StatusCode)
	}

	var providers []struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(resp, &providers); err != nil {
		t.Fatalf("decode providers: %v", err)
	}
	for _, p := range providers {
		if p.ID == "kiban-local-mfa-setup" {
			return
		}
	}
	t.Fatal("kiban-local-mfa-setup provider not found in the running Keycloak's authenticator-providers list")
}

// TestLive_ResolveAndStateRoundTrip proves the resolve + state round-trip against
// the LIVE stack for a realm test user. The kiban-identity-service service account IS a real
// Keycloak user in this realm (Keycloak creates one per service-account-enabled client) — using
// its own client_credentials token is a legitimate "realm test user" bearer without needing a
// separate password-grant test client wired into the foundation realm.
func TestLive_ResolveAndStateRoundTrip(t *testing.T) {
	cfg := loadKCConfig(t)
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	bearer, err := adminClient.token(ctx)
	if err != nil {
		t.Fatalf("fetch kiban-identity-service token: %v", err)
	}

	verifier, err := NewTokenVerifier(ctx,
		cfg.baseURL+"/realms/"+cfg.realm+"/protocol/openid-connect/certs",
		cfg.baseURL+"/realms/"+cfg.realm,
		"realm-management", // this service account's token audience — granted via its realm-management client roles
	)
	if err != nil {
		t.Fatalf("new token verifier: %v", err)
	}
	claims, err := verifier.Verify(ctx, bearer)
	if err != nil {
		t.Fatalf("verify live token: %v", err)
	}
	if claims.Sub == "" {
		t.Fatal("live token had no sub claim")
	}

	user, err := store.ResolveOrCreate(ctx, claims.Sub, claims.Email, claims.PreferredUsername)
	if err != nil {
		t.Fatalf("resolve-or-create: %v", err)
	}
	if user.KcSub != claims.Sub {
		t.Fatalf("resolved user kc_sub mismatch: got %q want %q", user.KcSub, claims.Sub)
	}

	state, err := store.ResolveUserState(ctx, adminClient, claims.Sub)
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.KCEnabled != KCStateTrue {
		t.Fatalf("expected the live service-account user to be enabled, got kcEnabled=%q", state.KCEnabled)
	}
	if state.Lifecycle != "active" {
		t.Fatalf("expected lifecycle=active for a freshly resolved user, got %q", state.Lifecycle)
	}
}

// TestLive_MfaSyncVisibleInKeycloak proves an MFA-required user's required_mode attribute set
// via sync is visible in Keycloak admin API, using the kiban.login_security.required_mode name
// and vocabulary the installed Java authenticator actually reads. This only proves visibility,
// not enforcement — the live enforcement proof is TestLive_MfaEnforcement* in this package.
func TestLive_MfaSyncVisibleInKeycloak(t *testing.T) {
	cfg := loadKCConfig(t)
	admin := adminPool(t)
	resetIdentityFixtures(t, admin)
	store := NewStore(identityPool(t))
	ctx := context.Background()

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	bearer, err := adminClient.token(ctx)
	if err != nil {
		t.Fatalf("fetch kiban-identity-service token: %v", err)
	}
	verifier, err := NewTokenVerifier(ctx,
		cfg.baseURL+"/realms/"+cfg.realm+"/protocol/openid-connect/certs",
		cfg.baseURL+"/realms/"+cfg.realm, "realm-management")
	if err != nil {
		t.Fatalf("new token verifier: %v", err)
	}
	claims, err := verifier.Verify(ctx, bearer)
	if err != nil {
		t.Fatalf("verify live token: %v", err)
	}

	user, err := store.ResolveOrCreate(ctx, claims.Sub, claims.Email, claims.PreferredUsername)
	if err != nil {
		t.Fatalf("resolve-or-create: %v", err)
	}
	if err := store.SetUserPolicy(ctx, user.ID, true, "otp", nil); err != nil {
		t.Fatalf("set user mfa policy: %v", err)
	}

	outcomes, err := store.SyncMfaPolicy(ctx, adminClient)
	if err != nil {
		t.Fatalf("sync mfa policy: %v", err)
	}
	found := false
	for _, o := range outcomes {
		if o.KcSub == claims.Sub {
			found = true
			if !o.Success {
				t.Fatalf("sync reported failure for %s: %s", claims.Sub, o.Error)
			}
			if !o.Required {
				t.Fatalf("sync outcome for %s should report required=true", claims.Sub)
			}
		}
	}
	if !found {
		t.Fatalf("sync did not report an outcome for %s", claims.Sub)
	}

	value, err := adminClient.GetUserAttribute(ctx, claims.Sub, RequiredModeAttribute)
	if err != nil {
		t.Fatalf("get user attribute via admin API: %v", err)
	}
	if value != "otp_required" {
		t.Fatalf("kiban.login_security.required_mode attribute not visible in Keycloak admin API as \"otp_required\": got %q", value)
	}
}
