// SPDX-License-Identifier: Apache-2.0

// Package gateway implements kiban-gateway: the single terminating edge. This file and
// catalog.go/proxy.go/middleware.go cover the JWKS token layer and the registry-driven
// dynamic module proxy + capability enforcement; the `/auth` reverse proxy, static/SPA serving,
// and the superadmin guard live in their own files, and TLS termination in cmd/gateway/main.go.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// JWKS operational numbers: 5s JWKS fetch timeout, 30s cooldown between retry
// attempts after a failed fetch (so a down JWKS endpoint isn't hammered on every request), 10m
// cache lifetime before a fetch is attempted again on an otherwise-healthy cache, 10s minimum
// between refetches triggered by a token whose `kid` the cached set does not carry (key
// rotation; a flood of garbage kids cannot hammer Keycloak faster than that), 30s clock-skew
// tolerance on iat/nbf/exp (Keycloak and the gateway rarely share a clock).
const (
	jwksFetchTimeout    = 5 * time.Second
	jwksCooldown        = 30 * time.Second
	jwksCacheTTL        = 10 * time.Minute
	jwksKidMissInterval = 10 * time.Second
	tokenAcceptableSkew = 30 * time.Second
)

// AuthContext is the server-derived actor identity attached to every validated request.
// Roles are deliberately never parsed here: the gateway, like every service in this codebase,
// must never use JWT roles/subject/email as an authorization source — this struct answers "who is this"
// for downstream forwarding/audit, never "what may they do".
type AuthContext struct {
	Subject           string
	Email             string
	PreferredUsername string
}

// ErrTokenMissing means no bearer token was presented at all (maps to 401
// AUTH_TOKEN_MISSING). ErrTokenInvalid covers every other validation failure — malformed,
// expired, bad signature, wrong issuer, wrong audience — collapsed to one sentinel at the same
// granularity the identity/authz verifiers use (maps to 401 AUTH_TOKEN_INVALID).
var (
	ErrTokenMissing = errors.New("gateway: bearer token missing")
	ErrTokenInvalid = errors.New("gateway: bearer token invalid")
)

// TokenVerifier validates access tokens against a remote JWKS (lestrrat-go/jwx),
// enforcing the exact fetch/cooldown/cache numbers above. The audience check is strict: only
// the literal configured `aud` value is accepted (jwt.WithAudience checks solely the `aud`
// claim) — `azp` is never consulted as an audience fallback, so an azp-only token is
// rejected.
type TokenVerifier struct {
	jwksURL  string
	issuer   string
	audience string
	client   *http.Client

	mu           sync.RWMutex
	set          jwk.Set
	fetchedAt    time.Time
	lastFailedAt time.Time

	// kidMissMu serialises unknown-kid refetches (single-flight: concurrent misses wait for the
	// one in progress, then re-check the set); lastKidRefetch rate-limits them.
	kidMissMu      sync.Mutex
	lastKidRefetch time.Time
}

// NewTokenVerifier fetches the JWKS once at construction, failing loudly if that fails — a
// gateway that cannot validate tokens must not start serving.
func NewTokenVerifier(ctx context.Context, jwksURL, issuer, audience string) (*TokenVerifier, error) {
	v := &TokenVerifier{
		jwksURL:  jwksURL,
		issuer:   issuer,
		audience: audience,
		client:   &http.Client{Timeout: jwksFetchTimeout},
	}
	if err := v.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("gateway: initial JWKS fetch from %s: %w", jwksURL, err)
	}
	return v, nil
}

// Refresh fetches the JWKS regardless of cache freshness — the initial fetch, ensureFresh's
// refresh, and cmd/gateway's periodic background goroutine all come through here.
func (v *TokenVerifier) Refresh(ctx context.Context) error {
	// Detached from the caller: a request that hangs up mid-fetch must not put the shared cache
	// into cooldown for everyone else. jwksFetchTimeout still bounds it.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksFetchTimeout)
	defer cancel()
	set, err := jwk.Fetch(fetchCtx, v.jwksURL, jwk.WithHTTPClient(v.client))

	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		v.lastFailedAt = time.Now()
		return err
	}
	v.set = set
	v.fetchedAt = time.Now()
	v.lastFailedAt = time.Time{}
	return nil
}

// ensureFresh refreshes the cached JWKS when it is older than jwksCacheTTL, unless a prior
// failed attempt is still within jwksCooldown — in which case the last known-good set (if any)
// keeps serving rather than retrying a down JWKS endpoint on every single request.
func (v *TokenVerifier) ensureFresh(ctx context.Context) error {
	v.mu.RLock()
	hasSet := v.set != nil
	stale := time.Since(v.fetchedAt) >= jwksCacheTTL
	inCooldown := !v.lastFailedAt.IsZero() && time.Since(v.lastFailedAt) < jwksCooldown
	v.mu.RUnlock()

	if hasSet && !stale {
		return nil
	}
	if inCooldown {
		if hasSet {
			return nil // serve the stale-but-known-good set during cooldown
		}
		return errors.New("gateway: JWKS unavailable (cooldown after a recent failed fetch)")
	}
	return v.Refresh(ctx)
}

func (v *TokenVerifier) currentSet() jwk.Set {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.set
}

// Verify parses and validates a compact JWS bearer token — signature, expiry, issuer, and a
// strict audience check — returning the AuthContext callers thread through as the validated
// actor identity. An empty bearerToken is ErrTokenMissing; every other failure is
// ErrTokenInvalid (both wrapped, so errors.Is still matches).
func (v *TokenVerifier) Verify(ctx context.Context, bearerToken string) (AuthContext, error) {
	if bearerToken == "" {
		return AuthContext{}, ErrTokenMissing
	}

	if err := v.ensureFresh(ctx); err != nil && v.currentSet() == nil {
		return AuthContext{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// A `kid` the cached set does not carry is what key rotation looks like from here: refetch
	// once (single-flight, at most every jwksKidMissInterval) before rejecting.
	if kid := unknownKid(bearerToken, v.currentSet()); kid != "" {
		v.refetchForKid(ctx)
	}

	token, err := jwt.Parse([]byte(bearerToken),
		jwt.WithKeySet(v.currentSet()),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(tokenAcceptableSkew),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil {
		return AuthContext{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	sub, ok := token.Subject()
	if !ok || sub == "" {
		return AuthContext{}, fmt.Errorf("%w: no sub claim", ErrTokenInvalid)
	}

	var email, preferredUsername string
	_ = token.Get("email", &email)
	_ = token.Get("preferred_username", &preferredUsername)

	return AuthContext{Subject: sub, Email: email, PreferredUsername: preferredUsername}, nil
}

// unknownKid returns the token's protected-header `kid` when the set has no key under it, ""
// otherwise (known kid, no kid, or a token too malformed to parse — jwt.Parse rejects those
// on its own).
func unknownKid(bearerToken string, set jwk.Set) string {
	msg, err := jws.ParseString(bearerToken)
	if err != nil || len(msg.Signatures()) == 0 || set == nil {
		return ""
	}
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return ""
	}
	if _, found := set.LookupKeyID(kid); found {
		return ""
	}
	return kid
}

// refetchForKid performs at most one JWKS refetch per jwksKidMissInterval, with concurrent
// callers waiting on the one in flight instead of starting their own. A failed fetch is
// already recorded by Refresh (cooldown); the caller proceeds with whatever set is current.
func (v *TokenVerifier) refetchForKid(ctx context.Context) {
	v.kidMissMu.Lock()
	defer v.kidMissMu.Unlock()
	if time.Since(v.lastKidRefetch) < jwksKidMissInterval {
		return
	}
	v.lastKidRefetch = time.Now()
	_ = v.Refresh(ctx)
}
