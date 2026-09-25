// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// TokenVerifier is authz's own copy of identity's bearer verifier (same
// lestrrat-go/jwx/v3 pattern, duplicated locally rather than importing internal/identity as a
// library — each service owns its own small infra helpers in this codebase, same as every
// dbtest_env.go). Actor identity for effective-access requests is ALWAYS this validated bearer
// subject (Forbidden: never accept an actor from a request body).
type TokenVerifier struct {
	jwksURL  string
	issuer   string
	audience string

	mu  sync.RWMutex
	set jwk.Set
}

// ErrTokenInvalid covers any bearer validation failure.
var ErrTokenInvalid = errors.New("authz: bearer token invalid")

func NewTokenVerifier(ctx context.Context, jwksURL, issuer, audience string) (*TokenVerifier, error) {
	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("authz: fetch JWKS from %s: %w", jwksURL, err)
	}
	return &TokenVerifier{jwksURL: jwksURL, issuer: issuer, audience: audience, set: set}, nil
}

func (v *TokenVerifier) Refresh(ctx context.Context) error {
	set, err := jwk.Fetch(ctx, v.jwksURL)
	if err != nil {
		return fmt.Errorf("authz: refresh JWKS: %w", err)
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

// Verify returns the validated subject (kcSub). azp is never treated as an audience fallback.
func (v *TokenVerifier) Verify(ctx context.Context, bearerToken string) (string, error) {
	if bearerToken == "" {
		return "", ErrTokenInvalid
	}
	token, err := jwt.Parse([]byte(bearerToken),
		jwt.WithKeySet(v.currentSet()),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil {
		return "", ErrTokenInvalid
	}
	sub, ok := token.Subject()
	if !ok || sub == "" {
		return "", ErrTokenInvalid
	}
	return sub, nil
}
