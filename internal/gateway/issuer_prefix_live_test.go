// SPDX-License-Identifier: Apache-2.0

//go:build live

package gateway

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestLive_IssuerAndPrefixes pins two contracts a standard OIDC client depends on, against the
// real kiban-test gateway (TokiDesk spike findings K14 and K15):
//
//  1. the discovery document at EITHER prefix (`/auth/realms/…` and `/realms/…`) advertises an
//     `issuer` equal to the `iss` inside a token the realm actually minted;
//  2. a browser login started on either prefix completes with a code and a token.
func TestLive_IssuerAndPrefixes(t *testing.T) {
	realm := platformLiveEnv(t, "KEYCLOAK_REALM")
	gwBase := "https://127.0.0.1:" + platformLiveEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	kcBase := "http://127.0.0.1:" + platformLiveEnv(t, "KEYCLOAK_HOST_PORT")
	adminBase := kcBase + "/admin/realms/" + realm

	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	tlsClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	kcAdminToken := platformKCAdminToken(t, plainHTTP, kcBase)
	username := platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME")
	userID := platformKCFindUser(t, plainHTTP, adminBase, kcAdminToken, username)
	if userID == "" {
		t.Fatalf("seeded superadmin %q not found in realm %q", username, realm)
	}
	password := "issuer-live-" + platformRandString(t, 16)
	platformKCSetPassword(t, plainHTTP, adminBase, kcAdminToken, userID, password)

	discovery := func(t *testing.T, prefix string) map[string]string {
		t.Helper()
		resp, err := tlsClient.Get(gwBase + prefix + "/realms/" + realm + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery via %q: %v", prefix, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET discovery via %q: HTTP %d", prefix, resp.StatusCode)
		}
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode discovery via %q: %v", prefix, err)
		}
		out := map[string]string{}
		for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
			v, _ := doc[k].(string)
			out[k] = v
		}
		return out
	}

	tokenIss := func(t *testing.T, token string) string {
		t.Helper()
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token is not a JWT")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode token payload: %v", err)
		}
		var claims struct {
			Iss string `json:"iss"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("unmarshal token payload: %v", err)
		}
		return claims.Iss
	}

	for _, prefix := range []string{"/auth", ""} {
		name := prefix
		if name == "" {
			name = "/realms (verbatim)"
		}
		t.Run("login started on "+name, func(t *testing.T) {
			token := platformInteractiveLoginAt(t, gwBase, prefix, realm, username, password)
			iss := tokenIss(t, token)
			doc := discovery(t, prefix)
			if doc["issuer"] != iss {
				t.Errorf("discovery issuer via %q = %q, token iss = %q; OIDC Discovery §4.3 requires them equal", prefix, doc["issuer"], iss)
			}
			for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
				if want := gwBase + prefix + "/realms/" + realm + "/protocol/openid-connect/"; !strings.HasPrefix(doc[k], want) {
					t.Errorf("discovery %s via %q = %q, want it under %q", k, prefix, doc[k], want)
				}
			}
			// The JWKS the document points at must serve the realm's keys on this prefix.
			resp, err := tlsClient.Get(doc["jwks_uri"])
			if err != nil {
				t.Fatalf("GET jwks_uri: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s = HTTP %d, want 200", doc["jwks_uri"], resp.StatusCode)
			}
		})
	}
}
