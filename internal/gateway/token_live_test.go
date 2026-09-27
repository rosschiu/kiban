// SPDX-License-Identifier: Apache-2.0

//go:build live

// Live proof for the token verifier: exercised against the REAL `make dev` Keycloak.
// Build-tag-fenced out of `make check`/`make test` — run explicitly with
// `go test -tags live ./internal/gateway/ -run TestLive -v`.
//
// This test uses the kiban-identity-service service-account client (bootstrapped by
// internal/identity) rather than a password-grant user or a "kiban-api"-audience token: mint a
// real token via that service account's client_credentials grant (audience "realm-management",
// granted through its client roles) and build a TokenVerifier for THAT audience rather than
// faking a production-shaped token. This still proves the thing that matters here — JWKS fetch,
// issuer check, and signature verification all work end-to-end against a real Keycloak — the
// piece a fake JWKS server can't prove.
package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fetchServiceAccountToken(t *testing.T, baseURL, realm, clientSecret string) string {
	t.Helper()
	form := url.Values{
		"client_id":     {"kiban-identity-service"},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(
		baseURL+"/realms/"+realm+"/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("fetch service-account token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch service-account token: status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body.AccessToken
}

// TestLive_TokenVerifier_RealKeycloak proves the JWKS/issuer/signature machinery against the
// real dev Keycloak: fetch the JWKS, mint a real service-account token, verify it end to end.
func TestLive_TokenVerifier_RealKeycloak(t *testing.T) {
	baseURL := "http://127.0.0.1:" + gatewayTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := gatewayTestEnv(t, "KEYCLOAK_REALM")
	clientSecret := gatewayTestEnv(t, "KEYCLOAK_IDENTITY_CLIENT_SECRET")

	jwksURL := baseURL + "/realms/" + realm + "/protocol/openid-connect/certs"
	issuer := baseURL + "/realms/" + realm

	// The service account's own token audience is "realm-management" (granted via its client
	// roles) — see the file-level comment. A production TokenVerifier is built with the
	// configured "kiban-api" audience; this live-only instance targets what the live token
	// actually carries, to prove the JWKS/issuer/signature path, not production audience
	// config (which needs no live Keycloak to test — see TestToken_AudienceStrict_* above).
	v, err := NewTokenVerifier(context.Background(), jwksURL, issuer, "realm-management")
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	tok := fetchServiceAccountToken(t, baseURL, realm, clientSecret)

	authCtx, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authCtx.Subject == "" {
		t.Error("expected a non-empty subject from a real Keycloak-issued token")
	}
}

// TestLive_TokenVerifier_WrongAudienceRejected proves the strict-audience check against a real
// token too: the same live token, verified against the production "kiban-api" audience it does
// NOT carry, must be rejected.
func TestLive_TokenVerifier_WrongAudienceRejected(t *testing.T) {
	baseURL := "http://127.0.0.1:" + gatewayTestEnv(t, "KEYCLOAK_HOST_PORT")
	realm := gatewayTestEnv(t, "KEYCLOAK_REALM")
	clientSecret := gatewayTestEnv(t, "KEYCLOAK_IDENTITY_CLIENT_SECRET")

	jwksURL := baseURL + "/realms/" + realm + "/protocol/openid-connect/certs"
	issuer := baseURL + "/realms/" + realm

	v, err := NewTokenVerifier(context.Background(), jwksURL, issuer, "kiban-api")
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	tok := fetchServiceAccountToken(t, baseURL, realm, clientSecret)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected the real token to be rejected for an audience it does not carry")
	}
}
