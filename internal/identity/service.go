// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// AdminAuthorizer guards the MFA-policy write/sync endpoints — same fail-closed seam as
// registry.AdminAuthorizer. denyAllAuthorizer is the fallback; the real implementation (an
// effective-access client call) is NewEngineAdminAuthorizer.
type AdminAuthorizer interface {
	// Can reports whether authCtx may perform action. A *DeniedError is a definite denial
	// (authz answered "not the superadmin", with its reason); any other non-nil error means the
	// authorizer could not reach a definite answer — callers must treat both as deny, never as
	// allow, and only the first as a 403.
	Can(ctx context.Context, authCtx AuthContext, action string) (bool, error)
}

// DeniedError is Can's confirmed denial: authz's own decision reason (e.g.
// PLATFORM_ROLE_REQUIRED), which the HTTP layer maps to 403 AUTHORIZATION_DENIED and audits.
type DeniedError struct {
	Reason string
}

func (e *DeniedError) Error() string {
	return "identity: authorization denied: " + e.Reason
}

// AuthContext is the server-derived actor identity threaded into authorization and audit calls
// — populated from a validated bearer (TokenVerifier), never from a request body.
type AuthContext struct {
	Subject string // kc_sub; empty means "no authenticated actor" — never treated as authority
	UserID  uuid.UUID

	// RawBearer is the inbound request's untouched "Authorization: Bearer ..." header value,
	// populated by http.go's mutation handlers straight from the request — never derived,
	// never from a request body. It exists so the real AdminAuthorizer
	// (internal/authz/client) can forward the SAME bearer to authz's effective-access endpoint
	// for a live platform-role check — same shape as internal/registry/adminauthz.go's
	// EffectiveAccessAuthorizer, which this package's AdminAuthorizer reuses via a thin
	// adapter (see NewEngineAdminAuthorizer).
	RawBearer string
}

// ErrAuthorizationUnavailable is the fail-closed sentinel the HTTP layer maps to 503
// AUTHORIZATION_UNAVAILABLE.
var ErrAuthorizationUnavailable = &authUnavailableError{}

type authUnavailableError struct{}

func (*authUnavailableError) Error() string {
	return "identity: authorization is unavailable (fail-closed guard)"
}

// denyAllAuthorizer is the fallback AdminAuthorizer: every call is uncertain, never a positive allow.
type denyAllAuthorizer struct{}

// NewDenyAllAuthorizer returns the fail-closed fallback AdminAuthorizer.
func NewDenyAllAuthorizer() AdminAuthorizer {
	return denyAllAuthorizer{}
}

func (denyAllAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, ErrAuthorizationUnavailable
}

// Service wires the store, the Keycloak admin client, the token verifier, the admin
// authorization guard, and the audit writer together for the HTTP handlers in http.go.
type Service struct {
	store    *Store
	admin    *AdminClient
	verifier *TokenVerifier
	authz    AdminAuthorizer
	audit    *audit.Writer
}

// NewService builds a Service. auditWriter must be constructed against
// "audit.identity__events" (see cmd/identity/main.go).
func NewService(store *Store, admin *AdminClient, verifier *TokenVerifier, authz AdminAuthorizer, auditWriter *audit.Writer) *Service {
	return &Service{store: store, admin: admin, verifier: verifier, authz: authz, audit: auditWriter}
}
