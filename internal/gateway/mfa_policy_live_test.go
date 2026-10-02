// SPDX-License-Identifier: Apache-2.0

//go:build live

package gateway

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestLive_MfaPolicyThroughGateway proves the second-factor policy is operable from the public
// surface alone: the superadmin sets the global policy and syncs it
// through the gateway, a user without an authenticator is then forced to enrol one at login,
// the per-user routes read/set/clear an override keyed by subject, and a plain user is refused.
// The policy is reset (and re-synced) on cleanup so the rest of the suite logs in unchallenged.
func TestLive_MfaPolicyThroughGateway(t *testing.T) {
	realm := platformLiveEnv(t, "KEYCLOAK_REALM")
	gwBase := "https://127.0.0.1:" + platformLiveEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	kcBase := "http://127.0.0.1:" + platformLiveEnv(t, "KEYCLOAK_HOST_PORT")
	adminBase := kcBase + "/admin/realms/" + realm

	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	tlsClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	kcAdmin := platformKCAdminToken(t, plainHTTP, kcBase)

	superadmin := platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME")
	superadminID := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, superadmin)
	superadminPassword := "mfa-live-" + platformRandString(t, 16)
	platformKCSetPassword(t, plainHTTP, adminBase, kcAdmin, superadminID, superadminPassword)
	adminBearer := platformInteractiveLogin(t, gwBase, realm, superadmin, superadminPassword)

	plainUsername := "mfa-plain-" + strings.ToLower(platformRandString(t, 8))
	plainPassword := "mfa-plain-" + platformRandString(t, 16)
	platformKCEnsurePlainUser(t, plainHTTP, adminBase, kcAdmin, plainUsername, plainPassword)
	plainBearer := platformInteractiveLogin(t, gwBase, realm, plainUsername, plainPassword) // also provisions the user in identity
	plainSub := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, plainUsername)

	call := func(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, gwBase+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := tlsClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var env map[string]any
		_ = json.Unmarshal(raw, &env)
		return resp.StatusCode, env
	}
	data := func(env map[string]any) map[string]any {
		d, _ := env["data"].(map[string]any)
		return d
	}

	// Reset whatever an earlier run left, and leave the realm unchallenged afterwards.
	reset := func() {
		call(t, http.MethodDelete, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, "")
		if st, _ := call(t, http.MethodPut, "/api/platform/admin/mfa-policy/global", adminBearer, `{"required":false}`); st != http.StatusOK {
			t.Errorf("reset global policy: HTTP %d", st)
		}
		if st, _ := call(t, http.MethodPost, "/api/platform/admin/mfa-policy/sync", adminBearer, ""); st != http.StatusOK {
			t.Errorf("reset sync: HTTP %d", st)
		}
	}
	reset()
	t.Cleanup(reset)

	t.Run("a plain user is refused", func(t *testing.T) {
		if st, _ := call(t, http.MethodGet, "/api/platform/admin/mfa-policy/global", plainBearer, ""); st != http.StatusForbidden {
			t.Fatalf("plain user GET global = HTTP %d, want 403", st)
		}
	})

	t.Run("global policy: set, read back, sync", func(t *testing.T) {
		st, env := call(t, http.MethodGet, "/api/platform/admin/mfa-policy/global", adminBearer, "")
		if st != http.StatusOK || data(env)["required"] != false {
			t.Fatalf("GET global before = HTTP %d %v, want required=false", st, env)
		}
		if st, env := call(t, http.MethodPut, "/api/platform/admin/mfa-policy/global", adminBearer, `{"required":true,"method":"totp"}`); st != http.StatusUnprocessableEntity {
			t.Fatalf("PUT global with a non-method = HTTP %d %v, want 422", st, env)
		}
		if st, env := call(t, http.MethodPut, "/api/platform/admin/mfa-policy/global", adminBearer, `{"required":true,"method":"otp"}`); st != http.StatusOK {
			t.Fatalf("PUT global = HTTP %d %v", st, env)
		}
		st, env = call(t, http.MethodGet, "/api/platform/admin/mfa-policy/global", adminBearer, "")
		if st != http.StatusOK || data(env)["required"] != true || data(env)["method"] != "otp" {
			t.Fatalf("GET global after = HTTP %d %v, want required=true method=otp", st, env)
		}
		st, env = call(t, http.MethodPost, "/api/platform/admin/mfa-policy/sync", adminBearer, "")
		outcomes, _ := env["data"].([]any)
		if st != http.StatusOK || len(outcomes) == 0 {
			t.Fatalf("POST sync = HTTP %d %v, want outcomes", st, env)
		}
		var synced bool
		for _, o := range outcomes {
			m, _ := o.(map[string]any)
			if m["KcSub"] == plainSub && m["Success"] == true && m["RequiredMode"] == "otp_required" {
				synced = true
			}
		}
		if !synced {
			t.Fatalf("sync outcomes carry no successful otp_required entry for %s: %v", plainSub, outcomes)
		}
	})

	t.Run("a user without an authenticator is made to enrol at login", func(t *testing.T) {
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		_, challenge := pkceVerifierAndChallenge(t)
		authURL := gwBase + "/auth/realms/" + realm + "/protocol/openid-connect/auth?" + url.Values{
			"client_id": {"kiban-frontend"}, "redirect_uri": {"http://localhost:5173/callback"}, "response_type": {"code"},
			"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"mfa-live"},
		}.Encode()
		resp, err := client.Get(authURL)
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := platformLoginFormActionRe.FindStringSubmatch(string(page))
		if m == nil {
			t.Fatalf("no login form: %s", page)
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		loginResp, err := client.PostForm(strings.ReplaceAll(m[1], "&amp;", "&"), url.Values{"username": {plainUsername}, "password": {plainPassword}, "credentialId": {""}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(loginResp.Body)
		loginResp.Body.Close()
		// Keycloak may answer the setup page directly or redirect to its required-action URL.
		if loc := loginResp.Header.Get("Location"); loc != "" && !strings.Contains(loc, "code=") {
			follow, err := client.Get(loc)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(follow.Body)
			follow.Body.Close()
		}
		if !regexp.MustCompile(`(?is)id="kc-totp-settings-form"`).MatchString(string(body)) {
			t.Fatalf("expected the authenticator setup page after password; status=%d Location=%q body head: %.400s", loginResp.StatusCode, loginResp.Header.Get("Location"), body)
		}
	})

	t.Run("per-user override by subject", func(t *testing.T) {
		if st, _ := call(t, http.MethodGet, "/api/platform/admin/mfa-policy/users/never-signed-in", adminBearer, ""); st != http.StatusNotFound {
			t.Fatalf("GET unknown subject = HTTP %d, want 404", st)
		}
		st, env := call(t, http.MethodGet, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, "")
		if st != http.StatusOK || data(env)["method"] != "otp" {
			t.Fatalf("GET user effective = HTTP %d %v, want the global otp policy", st, env)
		}
		if st, env := call(t, http.MethodPut, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, `{"required":false}`); st != http.StatusUnprocessableEntity {
			t.Fatalf("PUT weaker override = HTTP %d %v, want 422", st, env)
		}
		if st, env := call(t, http.MethodPut, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, `{"required":true,"method":"passkey"}`); st != http.StatusOK {
			t.Fatalf("PUT override = HTTP %d %v", st, env)
		}
		st, env = call(t, http.MethodGet, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, "")
		if st != http.StatusOK || data(env)["method"] != "passkey" {
			t.Fatalf("GET user after override = HTTP %d %v, want passkey", st, env)
		}
		if st, _ := call(t, http.MethodDelete, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, ""); st != http.StatusOK {
			t.Fatalf("DELETE override = HTTP %d", st)
		}
		st, env = call(t, http.MethodGet, "/api/platform/admin/mfa-policy/users/"+plainSub, adminBearer, "")
		if st != http.StatusOK || data(env)["method"] != "otp" {
			t.Fatalf("GET user after clear = HTTP %d %v, want the global otp policy again", st, env)
		}
	})
}
