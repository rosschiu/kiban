// SPDX-License-Identifier: Apache-2.0

package identity

import "testing"

// TestRequiredModeFor proves the mapping table: mfa_policy.Required/Method ->
// the exact required_mode string the installed Java authenticator's normalizeRequiredMode
// accepts (infra/keycloak-build/authenticator/.../KibanLocalMfaSetupAuthenticator.java ~104).
func TestRequiredModeFor(t *testing.T) {
	cases := []struct {
		name     string
		policy   MfaPolicy
		wantMode string
		wantErr  bool
	}{
		{"not required, no method", MfaPolicy{Required: false, Method: ""}, "none", false},
		{"not required, method set is irrelevant", MfaPolicy{Required: false, Method: "otp"}, "none", false},
		{"required otp", MfaPolicy{Required: true, Method: "otp"}, "otp_required", false},
		{"required passkey", MfaPolicy{Required: true, Method: "passkey"}, "passkey_required", false},
		{"required otp_or_passkey", MfaPolicy{Required: true, Method: "otp_or_passkey"}, "otp_or_passkey_required", false},
		{"required with empty method is refused", MfaPolicy{Required: true, Method: ""}, "", true},
		{"required with unrecognized method is refused", MfaPolicy{Required: true, Method: "sms"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requiredModeFor(tc.policy)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("requiredModeFor(%+v) = %q, nil; want an error", tc.policy, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("requiredModeFor(%+v) unexpected error: %v", tc.policy, err)
			}
			if got != tc.wantMode {
				t.Fatalf("requiredModeFor(%+v) = %q, want %q", tc.policy, got, tc.wantMode)
			}
		})
	}
}
