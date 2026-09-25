// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"

	"github.com/rosschiu/kiban/internal/audit"
)

// AdminAuthorizer guards the mutation endpoints (POST /internal/platform/modules/{key}/...).
// denyAllAuthorizer (see NewDenyAllAuthorizer) always returns an uncertain (false, non-nil)
// result, so the HTTP layer fails closed with 503 AUTHORIZATION_UNAVAILABLE rather than ever
// guessing allow. cmd/registry/main.go wires the real implementation (EffectiveAccessAuthorizer,
// adminauthz.go — an effective-access client call against authz), which reads
// AuthContext.RawBearer (populated in http.go's handleSetEnabled) to ask authz.
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
	return "registry: authorization denied: " + e.Reason
}

// AuthContext is the server-derived actor identity threaded into authorization and audit
// calls. It is deliberately minimal and is never populated from a request body.
type AuthContext struct {
	Subject string // empty means "no authenticated actor" — never treated as authority

	// RawBearer is the inbound request's untouched "Authorization: Bearer ..." header value.
	// It is populated ONLY by http.go's handleSetEnabled, straight from the
	// request the gateway already forwarded verbatim (platform_routes.go's newFixedProxy never
	// touches Authorization) — never derived, never from a request body. It exists so
	// EffectiveAccessAuthorizer (adminauthz.go) can forward the SAME bearer the gateway's own
	// admin guard already checked to authz's effective-access endpoint, for registry's own
	// independent (defense-in-depth) confirmation.
	RawBearer string
}

// ErrAuthorizationUnavailable is returned by denyAllAuthorizer.Can — the fail-closed sentinel
// the HTTP layer maps to 503 AUTHORIZATION_UNAVAILABLE.
var ErrAuthorizationUnavailable = &authUnavailableError{}

type authUnavailableError struct{}

func (*authUnavailableError) Error() string {
	return "registry: authorization is unavailable (fail-closed guard)"
}

// denyAllAuthorizer is the fail-closed AdminAuthorizer: every call is uncertain, never a
// positive allow.
type denyAllAuthorizer struct{}

// NewDenyAllAuthorizer returns the fail-closed AdminAuthorizer.
func NewDenyAllAuthorizer() AdminAuthorizer {
	return denyAllAuthorizer{}
}

func (denyAllAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, ErrAuthorizationUnavailable
}

// Service wires the store, the admin authorization guard, and the audit writer together for
// the HTTP handlers in http.go.
type Service struct {
	store *Store
	authz AdminAuthorizer
	audit *audit.Writer
}

// NewService builds a Service. auditWriter must be constructed against the
// "audit.registry__events" table (see cmd/registry/main.go).
func NewService(store *Store, authz AdminAuthorizer, auditWriter *audit.Writer) *Service {
	return &Service{store: store, authz: authz, audit: auditWriter}
}
