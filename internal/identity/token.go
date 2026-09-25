// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims is the subset of a validated bearer token's claims the identity service needs.
// Identity comes ONLY from the validated bearer — never a request body.
type Claims struct {
	Sub               string // kc_sub
	Email             string
	PreferredUsername string
}

// ErrTokenInvalid is returned for any bearer validation failure (missing/malformed/expired/
// wrong audience/wrong issuer/bad signature) — collapsed to one sentinel because errenv only
// defines CodeAuthTokenInvalid at this contract's granularity today (see internal/errenv).
var ErrTokenInvalid = errors.New("identity: bearer token invalid")

// TokenVerifier validates access tokens against a remote JWKS (lestrrat-go/jwx),
// checking issuer and audience. It never trusts JWT roles/subject/email as authority beyond
// "this is who the token says it is" — authorization decisions are the caller's job.
type TokenVerifier struct {
	jwksURL  string
	issuer   string
	audience string

	mu  sync.RWMutex
	set jwk.Set
}

// NewTokenVerifier fetches the JWKS once at construction (failing loudly if that fails — a
// service that can't validate tokens shouldn't start serving) and keeps it in memory; call
// Refresh periodically (e.g. from a background goroutine in cmd/identity) to pick up rotation.
func NewTokenVerifier(ctx context.Context, jwksURL, issuer, audience string) (*TokenVerifier, error) {
	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("identity: fetch JWKS from %s: %w", jwksURL, err)
	}
	return &TokenVerifier{jwksURL: jwksURL, issuer: issuer, audience: audience, set: set}, nil
}

// Refresh re-fetches the JWKS, replacing the in-memory set on success. A failed refresh keeps
// serving the last known-good set (transient JWKS-endpoint blips must not take down token
// validation for already-rotated-in keys).
func (v *TokenVerifier) Refresh(ctx context.Context) error {
	set, err := jwk.Fetch(ctx, v.jwksURL)
	if err != nil {
		return fmt.Errorf("identity: refresh JWKS: %w", err)
	}
	v.mu.Lock()
	v.set = set
	v.mu.Unlock()
	return nil
}

func (v *TokenVerifier) currentSet() jwk.Set {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.set
}

// Verify parses and validates a compact JWS bearer token (aud must contain the configured
// audience; azp is NEVER treated as an audience fallback), returning the
// claims the identity service needs. Any failure collapses to ErrTokenInvalid.
func (v *TokenVerifier) Verify(ctx context.Context, bearerToken string) (Claims, error) {
	if bearerToken == "" {
		return Claims{}, ErrTokenInvalid
	}
	token, err := jwt.Parse([]byte(bearerToken),
		jwt.WithKeySet(v.currentSet()),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	sub, ok := token.Subject()
	if !ok || sub == "" {
		return Claims{}, fmt.Errorf("%w: no sub claim", ErrTokenInvalid)
	}

	var email, preferredUsername string
	_ = token.Get("email", &email)
	_ = token.Get("preferred_username", &preferredUsername)

	return Claims{Sub: sub, Email: email, PreferredUsername: preferredUsername}, nil
}
