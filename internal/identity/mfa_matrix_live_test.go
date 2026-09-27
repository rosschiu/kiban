// SPDX-License-Identifier: Apache-2.0

//go:build live

// The enforcement matrix: for each required_mode x credential state (no credential /
// wrong-type credential / right-type credential), assert the login flow challenges (forces
// setup) or passes (does not). Extends mfa_enforcement_live_test.go's cookie-jar login technique
// (mfaEnforcementLoginAttempt, mfaEnforcementTOTPSetupMarkerRe, mfaEnforcementKCUser,
// mfaEnforcementTruncate) with fresh, credential-seeded Keycloak users. Run against the ISOLATED
// kiban-test stack ONLY — never `make dev`/the public deployment.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// mfaEnforcementWebAuthnRegisterMarkerRe matches Keycloak's built-in WebAuthn *registration*
// required-action page (register-webauthn.ftl renders a button with this id) — the
// REGISTER_PASSKEY setup marker, distinct from any WebAuthn *authentication* challenge page
// (which this matrix never has to distinguish from, see mfaEnforcementNotSetupChallenged).
var mfaEnforcementWebAuthnRegisterMarkerRe = regexp.MustCompile(`(?is)id="registerWebAuthn"`)

// mfaEnforcementNotSetupChallenged asserts the login response is NOT one of the authenticator's
// setup pages (CONFIGURE_TOTP / webauthn-register-passwordless) — i.e. the required_mode was
// satisfied by the seeded credential, whether that resolves as an immediate redirect to the
// app's callback (confirmed live for the passkey_required + existing-passkey cell) or as
// Keycloak's OWN separate runtime credential challenge (e.g. the built-in OTP-entry page,
// id="kc-otp-login-form", confirmed live for the otp_required + existing-OTP cell) — a
// DIFFERENT flow execution than this authenticator's required-action setup enforcement,
// triggered because the realm's browser flow also has its own conditional MFA-challenge subflow
// keyed on the same stored credential (setup vs challenge separation). This matrix is about
// setup enforcement only, so either outcome counts as "satisfied" here.
func mfaEnforcementNotSetupChallenged(t *testing.T, status int, body string) {
	t.Helper()
	if mfaEnforcementTOTPSetupMarkerRe.MatchString(body) {
		t.Fatalf("expected the credential to satisfy the policy (no OTP setup forced), but got the TOTP-setup page; status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
	}
	if mfaEnforcementWebAuthnRegisterMarkerRe.MatchString(body) {
		t.Fatalf("expected the credential to satisfy the policy (no passkey setup forced), but got the WebAuthn-register page; status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
	}
}

// mfaEnforcementCredentialSeed is one extra credential (beyond the always-present password) to
// create a matrix test user with. Keycloak's user-create REST endpoint accepts raw
// credentialData/secretData JSON in a CredentialRepresentation and stores it via a raw insert
// (the same path realm import uses to pre-seed TOTP/WebAuthn credentials in test realms —
// confirmed empirically against the running kiban-test Keycloak before writing this matrix: a
// created user's GET .../credentials lists the seeded otp/webauthn-passwordless row, and
// user.credentialManager().getStoredCredentialsByTypeStream(...) — what the authenticator
// actually calls — resolves off that same stored row). No real TOTP/WebAuthn ceremony is
// needed for the cells that use this: they only assert on required-action ENFORCEMENT (does the
// authenticator treat the credential as present), never on completing an OTP/WebAuthn challenge.
type mfaEnforcementCredentialSeed struct {
	credType       string
	credentialData string
	secretData     string
}

func mfaEnforcementOtpCredentialSeed() mfaEnforcementCredentialSeed {
	return mfaEnforcementCredentialSeed{
		credType:       "otp",
		credentialData: `{"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"}`,
		secretData:     `{"value":"MFAMATRIXSECRET"}`,
	}
}

func mfaEnforcementPasskeyCredentialSeed() mfaEnforcementCredentialSeed {
	return mfaEnforcementCredentialSeed{
		credType:       "webauthn-passwordless",
		credentialData: `{"aaguid":"00000000-0000-0000-0000-000000000000","credentialId":"AAAAAAAAAAAAAAAAAAAAAA","counter":0,"attestationStatement":"{}","attestationStatementFormat":"none","credentialPublicKey":"AAAAAAAAAAAAAAAAAAAAAA","transports":[]}`,
		secretData:     `{}`,
	}
}

// mfaEnforcementSeedUser creates a FRESH Keycloak user (deleting any prior user of the same
// name first, so repeated runs never accumulate stale credentials/attributes) with the given
// kiban.login_security.required_mode attribute, an optional extra stored credential, and an
// optional kiban.login_security.mfa RUNTIME_MFA_ATTRIBUTE override (see TestLive_MfaEnforcementMatrix
// for why the "wrong type OTP credential" cell uses the override instead of a real stored OTP
// credential). firstName/lastName are set explicitly: an admin-API-created user missing them
// gets Keycloak's own VERIFY_PROFILE required action queued ahead of anything this authenticator
// decides — a behavior unrelated to MFA enforcement, confirmed empirically against this realm's
// user-profile config (a bare password-only user with no firstName/lastName redirected to
// login-actions/required-action?execution=VERIFY_PROFILE even under required_mode=none) before
// writing this helper. Uses the app-realm service-account AdminClient (never master-realm
// credentials), same precedent as mfaEnforcementEnsureTestUser.
func mfaEnforcementSeedUser(ctx context.Context, t *testing.T, admin *AdminClient, cfg kcConfig, username, requiredMode string, cred *mfaEnforcementCredentialSeed, mfaOverride string) mfaEnforcementKCUser {
	t.Helper()
	password := "mfa-matrix-" + mfaEnforcementPKCEVerifier(t)[:20]
	token, err := admin.token(ctx)
	if err != nil {
		t.Fatalf("fetch admin token: %v", err)
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}

	findURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true", cfg.baseURL, cfg.realm, url.QueryEscape(username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, findURL, nil)
	if err != nil {
		t.Fatalf("build find-user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("find existing matrix user: %v", err)
	}
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&found); err != nil {
		resp.Body.Close()
		t.Fatalf("decode find-user response: %v", err)
	}
	resp.Body.Close()
	for _, f := range found {
		delReq, delErr := http.NewRequestWithContext(ctx, http.MethodDelete, fmt.Sprintf("%s/admin/realms/%s/users/%s", cfg.baseURL, cfg.realm, f.ID), nil)
		if delErr != nil {
			continue
		}
		delReq.Header.Set("Authorization", "Bearer "+token)
		if delResp, delErr := httpClient.Do(delReq); delErr == nil {
			delResp.Body.Close()
		}
	}

	credentials := []map[string]any{{"type": "password", "value": password, "temporary": false}}
	if cred != nil {
		credentials = append(credentials, map[string]any{
			"type":           cred.credType,
			"credentialData": cred.credentialData,
			"secretData":     cred.secretData,
		})
	}
	// mfaRuntimeAttribute is the Java authenticator's RUNTIME_MFA_ATTRIBUTE
	// ("kiban.login_security.mfa") — not written by sync.go, so no exported Go constant exists
	// for it; inlined here as a literal since this test file is its only caller in this package.
	const mfaRuntimeAttribute = "kiban.login_security.mfa"
	attributes := map[string][]string{RequiredModeAttribute: {requiredMode}}
	if mfaOverride != "" {
		attributes[mfaRuntimeAttribute] = []string{mfaOverride}
	}
	createBody, _ := json.Marshal(map[string]any{
		"username":        username,
		"email":           username + "@example.invalid",
		"enabled":         true,
		"emailVerified":   true,
		"firstName":       "Kiban",
		"lastName":        "MFA Matrix",
		"requiredActions": []string{},
		"attributes":      attributes,
		"credentials":     credentials,
	})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/admin/realms/%s/users", cfg.baseURL, cfg.realm), strings.NewReader(string(createBody)))
	if err != nil {
		t.Fatalf("build create-user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatalf("create matrix user: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create matrix user: status %d, body: %s", resp.StatusCode, mfaEnforcementTruncate(string(body), 1000))
	}
	loc := resp.Header.Get("Location")
	parts := strings.Split(loc, "/")
	return mfaEnforcementKCUser{ID: parts[len(parts)-1], Username: username, Password: password}
}

// TestLive_MfaEnforcementMatrix is the full required_mode x credential-state matrix, every cell
// proven live. One cell ("passkey-req-wrongtype") cannot use a real stored OTP credential
// be used to observe the authenticator's own decision: Keycloak's browser flow has ITS OWN
// conditional OTP-challenge execution that fires for any user with a stored OTP credential
// regardless of kiban's required_mode policy, and that native challenge runs BEFORE this
// authenticator's required-action decision is reachable in the response — confirmed empirically
// against the running kiban-test Keycloak (a user with a real seeded OTP credential landed on
// Keycloak's own id="kc-otp-login-form" runtime-challenge page, never on the setup page this
// cell needs to assert on, even under passkey_required). That one cell instead sets the
// RUNTIME_MFA_ATTRIBUTE override (kiban.login_security.mfa=otp) with NO stored OTP credential —
// a real, explicitly-supported input to resolveCredentialState's own override branch (Java
// source, KibanLocalMfaSetupAuthenticator.java) — which exercises the exact same "hasOtp=true,
// hasPasskey=false" decision the authenticator would compute from a real credential, without
// triggering Keycloak's unrelated native OTP-entry subflow.
func TestLive_MfaEnforcementMatrix(t *testing.T) {
	cfg := loadKCConfig(t)
	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	ctx := context.Background()

	otpSeed := mfaEnforcementOtpCredentialSeed()
	passkeySeed := mfaEnforcementPasskeyCredentialSeed()

	cases := []struct {
		slug         string
		requiredMode string
		cred         *mfaEnforcementCredentialSeed
		mfaOverride  string
		assert       func(t *testing.T, status int, body string)
	}{
		{"otp-req-nocred", "otp_required", nil, "", func(t *testing.T, status int, body string) {
			if !mfaEnforcementTOTPSetupMarkerRe.MatchString(body) {
				t.Fatalf("expected the TOTP-setup page; status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
			}
		}},
		{"otp-req-wrongtype", "otp_required", &passkeySeed, "", func(t *testing.T, status int, body string) {
			if !mfaEnforcementTOTPSetupMarkerRe.MatchString(body) {
				t.Fatalf("an existing PASSKEY must not satisfy otp_required; expected the TOTP-setup page, status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
			}
		}},
		{"otp-req-righttype", "otp_required", &otpSeed, "", func(t *testing.T, status int, body string) {
			mfaEnforcementNotSetupChallenged(t, status, body)
		}},
		{"passkey-req-nocred", "passkey_required", nil, "", func(t *testing.T, status int, body string) {
			if !mfaEnforcementWebAuthnRegisterMarkerRe.MatchString(body) {
				t.Fatalf("expected the WebAuthn-register page; status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
			}
		}},
		{"passkey-req-wrongtype", "passkey_required", nil, "otp", func(t *testing.T, status int, body string) {
			if !mfaEnforcementWebAuthnRegisterMarkerRe.MatchString(body) {
				t.Fatalf("an existing OTP credential must not satisfy passkey_required; expected the WebAuthn-register page, status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
			}
		}},
		{"passkey-req-righttype", "passkey_required", &passkeySeed, "", func(t *testing.T, status int, body string) {
			mfaEnforcementNotSetupChallenged(t, status, body)
		}},
		{"either-req-nocred", "otp_or_passkey_required", nil, "", func(t *testing.T, status int, body string) {
			// The authenticator's deterministic default: a true two-way chooser is not
			// achievable with plain required-action mechanics, so the no-credential case
			// defaults to CONFIGURE_TOTP.
			if !mfaEnforcementTOTPSetupMarkerRe.MatchString(body) {
				t.Fatalf("expected the deterministic OTP-setup default; status=%d body:\n%s", status, mfaEnforcementTruncate(body, 3000))
			}
		}},
		{"either-req-otp", "otp_or_passkey_required", &otpSeed, "", func(t *testing.T, status int, body string) {
			mfaEnforcementNotSetupChallenged(t, status, body)
		}},
		{"either-req-passkey", "otp_or_passkey_required", &passkeySeed, "", func(t *testing.T, status int, body string) {
			mfaEnforcementNotSetupChallenged(t, status, body)
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.slug, func(t *testing.T) {
			username := "kiban-mfa-matrix-" + tc.slug
			kcUser := mfaEnforcementSeedUser(ctx, t, adminClient, cfg, username, tc.requiredMode, tc.cred, tc.mfaOverride)
			status, _, body := mfaEnforcementLoginAttempt(t, cfg, kcUser.Username, kcUser.Password)
			tc.assert(t, status, body)
		})
	}
}
