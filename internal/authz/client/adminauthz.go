// SPDX-License-Identifier: Apache-2.0

// Package client is the shared "is this caller the platform superadmin" AdminAuthorizer
// implementation, used by org, identity, registry and the gateway's superadmin guard. One
// HTTP round trip (call authz's POST /internal/authz/effective-access/can with scope "global"
// and the platform-superadmin feature key/role, forward the caller's raw bearer verbatim, fail
// closed on anything but a well-formed 200 envelope) behind thin package-local adapters
// (AdminAuthorizer's method signature names each package's own AuthContext type, so Go
// structural typing can't share the interface itself across packages; the HTTP logic is what's
// shared).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// AdminFeatureKey / AdminRequiredRole — every admin guard in the platform asks authz the
// identical question.
const (
	AdminFeatureKey   = "auth.platform_administration.access"
	AdminRequiredRole = "kiban-superadmin"

	defaultTimeout = 5 * time.Second
)

// ErrAuthorizationUnavailable is the fail-closed sentinel every caller of Can must treat as deny
// (never allow) — Can itself never returns a bare bool with a nil error meaning uncertainty; a
// non-nil error always means exactly this.
var ErrAuthorizationUnavailable = errors.New("authz client: authorization is unavailable")

// AdminAuthorizer calls authz's effective-access/can endpoint to answer "does the bearer belong
// to the platform superadmin". It is deliberately NOT itself org.AdminAuthorizer or
// identity.AdminAuthorizer (those interfaces name package-local AuthContext types) — each
// package wraps this in a one-method adapter, see internal/org/adminauthz.go and
// internal/identity/adminauthz.go.
type AdminAuthorizer struct {
	baseURL string
	client  *http.Client
}

// New builds an AdminAuthorizer against authz's base URL (e.g. "http://authz:8140" in compose,
// "http://127.0.0.1:8140" for a host-run process). A nil httpClient gets a bounded-timeout
// default (same 5s every other internal client in this codebase uses).
func New(baseURL string, httpClient *http.Client) *AdminAuthorizer {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &AdminAuthorizer{baseURL: baseURL, client: httpClient}
}

type canRequestWire struct {
	FeatureKey           string `json:"featureKey"`
	Scope                string `json:"scope"`
	RequiredPlatformRole string `json:"requiredPlatformRole"`
	Action               string `json:"action"`
	CorrelationID        string `json:"correlationId,omitempty"`
}

type canResponseWire struct {
	Data struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	} `json:"data"`
}

// Decision is authz's own answer, exactly as decoded from a well-formed 200 envelope. Allowed is
// authoritative only together with Reason == "ALLOWED" (see Can); a false Allowed carries the
// decision's reason code so a caller that distinguishes a confirmed denial from uncertainty (the
// gateway's 403-vs-503) can inspect it.
type Decision struct {
	Allowed bool
	Reason  string
}

// knownDenialReasons are the only reason codes the ScopeGlobal branch of authz's decision
// (internal/authz/decision/evaluate.go) can actually return as a denial: AUTH_USER_NOT_FOUND,
// KEYCLOAK_DISABLED, USER_LIFECYCLE_DISABLED (steps 1-3, scope-independent), and
// PLATFORM_ROLE_REQUIRED (step 4, the global-scope leg itself). Anything else in the "denied"
// position (a reason this package doesn't recognize, most notably DEPENDENCY_UNAVAILABLE — which
// never reaches here, since authz's own HTTP layer maps it to a non-200 status Decide already
// treats as unavailable before ever inspecting `reason`) is uncertain, not a confirmed denial.
var knownDenialReasons = map[string]bool{
	"AUTH_USER_NOT_FOUND":     true,
	"KEYCLOAK_DISABLED":       true,
	"USER_LIFECYCLE_DISABLED": true,
	"PLATFORM_ROLE_REQUIRED":  true,
}

// Denied reports a CONFIRMED denial: authz answered, and the reason is one it produces for
// "this bearer is not the platform superadmin". A caller that distinguishes 403 from 503 treats
// exactly this as the 403; everything that is neither Denied nor an ALLOWED envelope stays
// uncertain (fail-closed 503).
func (d Decision) Denied() bool {
	return !d.Allowed && knownDenialReasons[d.Reason]
}

// Decide asks authz's effective-access/can whether rawBearer (the inbound request's untouched
// "Authorization: Bearer ..." header value) belongs to the platform superadmin, per authz's live
// effective-access decision (decision.ScopeGlobal — subject lookup, Keycloak-enabled, lifecycle,
// then a platform-role match against AdminRequiredRole; see internal/authz/decision/evaluate.go).
// action is carried through only for the caller's own audit trail — it plays no role in the
// decision itself. correlationID, when non-empty, is forwarded in the body and as
// x-correlation-id.
//
// Fail-closed: an empty bearer, any transport/decode failure, or any non-200 status returns
// ErrAuthorizationUnavailable (never a fabricated allow). Non-200 covers authz's own
// DEPENDENCY_UNAVAILABLE => 503 mapping (internal/authz/http.go's writeDecision) along with every
// other transport-level failure (401, 500, ...).
func (a *AdminAuthorizer) Decide(ctx context.Context, rawBearer, action, correlationID string) (Decision, error) {
	if rawBearer == "" {
		return Decision{}, ErrAuthorizationUnavailable
	}

	body, err := json.Marshal(canRequestWire{
		FeatureKey:           AdminFeatureKey,
		Scope:                "global",
		RequiredPlatformRole: AdminRequiredRole,
		Action:               action,
		CorrelationID:        correlationID,
	})
	if err != nil {
		return Decision{}, ErrAuthorizationUnavailable
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/internal/authz/effective-access/can", bytes.NewReader(body))
	if err != nil {
		return Decision{}, ErrAuthorizationUnavailable
	}
	req.Header.Set("Authorization", rawBearer)
	req.Header.Set("Content-Type", "application/json")
	if correlationID != "" {
		req.Header.Set("x-correlation-id", correlationID)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return Decision{}, ErrAuthorizationUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Decision{}, ErrAuthorizationUnavailable
	}

	var envelope canResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return Decision{}, ErrAuthorizationUnavailable
	}
	return Decision(envelope.Data), nil
}

// Can reports whether rawBearer belongs to the platform superadmin. Fail-closed: everything
// Decide fails on, plus any response that isn't an explicit ALLOWED envelope, returns (false,
// ErrAuthorizationUnavailable) — never a bare "false, nil" a caller could mistake for a
// confident deny.
func (a *AdminAuthorizer) Can(ctx context.Context, rawBearer, action string) (bool, error) {
	d, err := a.Decide(ctx, rawBearer, action, "")
	if err != nil {
		return false, err
	}
	if d.Allowed && d.Reason == "ALLOWED" {
		return true, nil
	}
	return false, ErrAuthorizationUnavailable
}
