// SPDX-License-Identifier: Apache-2.0

//go:build live

package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
)

// A password grant (direct access grant) cannot bypass MFA setup. The realm's
// direct-grant flow carries the same MFA-setup authenticator as the browser flow, so for a user
// under a required policy with no enrolled credential Keycloak refuses the grant ("Account is
// not fully set up") instead of issuing a token — through ANY direct-grant client, here the
// realm's built-in public admin-cli (the proof scripts' throwaway clients are the same case).
// A user under required_mode=none still gets a token (the proofs keep working).
func TestLive_MfaEnforcement_DirectGrantRefusedWithoutSetup(t *testing.T) {
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}
	cfg := loadKCConfig(t)
	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	ctx := context.Background()

	passwordGrant := func(user mfaEnforcementKCUser) (int, map[string]any) {
		resp, err := http.PostForm(cfg.baseURL+"/realms/"+cfg.realm+"/protocol/openid-connect/token", url.Values{
			"grant_type": {"password"}, "client_id": {"admin-cli"},
			"username": {user.Username}, "password": {user.Password},
		})
		if err != nil {
			t.Fatalf("token request: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return resp.StatusCode, body
	}

	needsSetup := mfaEnforcementSeedUser(ctx, t, adminClient, cfg, "dg-otp-required", "otp_required", nil, "")
	status, body := passwordGrant(needsSetup)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" || !strings.Contains(strings.ToLower(body["error_description"].(string)), "not fully set up") {
		t.Fatalf("password grant for an otp_required user with no OTP: status=%d body=%v, want 400 invalid_grant \"Account is not fully set up\"", status, body)
	}
	if _, has := body["access_token"]; has {
		t.Fatal("a token was issued despite the pending MFA setup")
	}

	noPolicy := mfaEnforcementSeedUser(ctx, t, adminClient, cfg, "dg-none", "none", nil, "")
	status, body = passwordGrant(noPolicy)
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("password grant for a required_mode=none user: status=%d body=%v, want 200 with a token", status, body)
	}
}
