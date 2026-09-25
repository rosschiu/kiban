// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// RequiredModeAttribute is the Keycloak user attribute the effective MFA policy syncs to. It
// must match the REQUIRED_MODE_ATTRIBUTE the installed Java authenticator
// (infra/keycloak-build/authenticator/.../KibanLocalMfaSetupAuthenticator.java) reads — a
// single vocabulary on both sides. Value is one of the authenticator's own required-mode
// vocabulary: "none", "otp_required", "passkey_required", "otp_or_passkey_required" — see
// requiredModeFor.
const RequiredModeAttribute = "kiban.login_security.required_mode"

// SyncOutcome is one user's sync result — truthful partial reporting (no claimed success on
// partial failure). Callers must inspect every element, not just whether
// Sync returned a nil error.
type SyncOutcome struct {
	UserID       uuid.UUID
	KcSub        string
	Required     bool
	RequiredMode string
	Success      bool
	Error        string
}

// requiredModeFor maps an effective MfaPolicy to the exact required_mode string value the
// installed Java authenticator's normalizeRequiredMode accepts:
//
//	Required=false                       -> "none"                     (any Method value)
//	Required=true, Method="otp"           -> "otp_required"
//	Required=true, Method="passkey"       -> "passkey_required"
//	Required=true, Method="otp_or_passkey" -> "otp_or_passkey_required"
//	Required=true, Method="" or anything else -> error (VALIDATION_FAILED semantics: an
//	  unenforceable/unset method under a required policy is refused rather than
//	  silently accepted — the Java side would otherwise fail closed to "passkey_required" behind
//	  our back, which is safe but not what was requested, and not truthful to report as Success).
func requiredModeFor(policy MfaPolicy) (string, error) {
	if !policy.Required {
		return "none", nil
	}
	switch policy.Method {
	case "otp":
		return "otp_required", nil
	case "passkey":
		return "passkey_required", nil
	case "otp_or_passkey":
		return "otp_or_passkey_required", nil
	default:
		return "", fmt.Errorf("identity: mfa policy required=true has no enforceable method (want one of otp, passkey, otp_or_passkey, got %q)", policy.Method)
	}
}

// SyncMfaPolicy writes every user's effective MFA policy (user override if present else global
// — the layering EffectivePolicy resolves) to their Keycloak RequiredModeAttribute, mapped via
// requiredModeFor. It is idempotent (re-running with unchanged policy re-writes the same value)
// and NEVER aborts on one user's failure — every user gets an attempt, and the returned outcomes
// report each one truthfully, including mapping failures (a required policy with no enforceable
// method), which are reported as a failed outcome rather than silently written or skipped.
func (s *Store) SyncMfaPolicy(ctx context.Context, admin *AdminClient) ([]SyncOutcome, error) {
	inputs, err := s.ListEffectivePolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: sync mfa policy: %w", err)
	}

	outcomes := make([]SyncOutcome, 0, len(inputs))
	for _, in := range inputs {
		mode, err := requiredModeFor(in.Policy)
		if err != nil {
			outcomes = append(outcomes, SyncOutcome{
				UserID: in.UserID, KcSub: in.KcSub, Required: in.Policy.Required,
				Success: false, Error: err.Error(),
			})
			continue
		}
		err = admin.SetUserAttribute(ctx, in.KcSub, RequiredModeAttribute, mode)
		outcome := SyncOutcome{
			UserID: in.UserID, KcSub: in.KcSub, Required: in.Policy.Required,
			RequiredMode: mode, Success: err == nil,
		}
		if err != nil {
			outcome.Error = err.Error()
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}
