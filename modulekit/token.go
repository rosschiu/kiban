// SPDX-License-Identifier: Apache-2.0

// Package modulekit is the scaffolding every Kiban module service needs and used to copy: bearer
// verification, the small HTTP/pg helpers, and thin clients for org's member facts, authz's
// effective-access/grants API and notification's targeted-events API. Every constructor takes the
// module key, which prefixes error strings ("<moduleKey>: ...") and, where the platform wire
// carries it, is sent as moduleKey/sourceModule. Modules never treat JWT roles as authority — the
// verifier answers "who is the caller" (kcSub only), never "what may they do".
package modulekit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// DefaultJWKSRefreshInterval matches the gateway's own periodic refresh cadence, so a key rotated
// at the IdP is picked up without a process restart.
const DefaultJWKSRefreshInterval = 10 * time.Minute

// ErrTokenInvalid covers any bearer validation failure (missing, malformed, expired, wrong
// issuer/audience, bad signature). Verify returns it wrapped as "<moduleKey>: bearer token
// invalid"; match with errors.Is.
var ErrTokenInvalid = errors.New("bearer token invalid")

// TokenVerifier validates bearer tokens against a JWKS (lestrrat-go/jwx/v3).
type TokenVerifier struct {
	prefix   string
	jwksURL  string
	issuer   string
	audience string
	errInval error

	mu  sync.RWMutex
	set jwk.Set
}

// NewTokenVerifier fetches the JWKS once at construction, failing loudly if that fails.
func NewTokenVerifier(ctx context.Context, jwksURL, issuer, audience, moduleKey string) (*TokenVerifier, error) {
	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%s: fetch JWKS from %s: %w", moduleKey, jwksURL, err)
	}
	return &TokenVerifier{
		prefix: moduleKey, jwksURL: jwksURL, issuer: issuer, audience: audience,
		errInval: fmt.Errorf("%s: %w", moduleKey, ErrTokenInvalid),
		set:      set,
	}, nil
}

func (v *TokenVerifier) currentSet() jwk.Set {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.set
}

// Refresh forces a JWKS re-fetch regardless of cache age — wired to a periodic background
// goroutine (RefreshPeriodically) and also called once, inline, by Verify itself on an
// unknown-kid failure.
func (v *TokenVerifier) Refresh(ctx context.Context) error {
	set, err := jwk.Fetch(ctx, v.jwksURL)
	if err != nil {
		return fmt.Errorf("%s: refresh JWKS from %s: %w", v.prefix, v.jwksURL, err)
	}
	v.mu.Lock()
	v.set = set
	v.mu.Unlock()
	return nil
}

// RefreshPeriodically re-fetches the JWKS on a fixed interval until ctx is done. A failed refresh
// is logged and the previous key set keeps serving.
func (v *TokenVerifier) RefreshPeriodically(ctx context.Context, logger *slog.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := v.Refresh(ctx); err != nil {
				logger.Warn(v.prefix+": jwks refresh failed", slog.Any("error", err))
			}
		}
	}
}

// isUnknownKidError matches jwx v3's jws key-lookup failure message ("failed to find key with
// key ID %q in key set") — jwx exposes no sentinel error type for this, so a substring match is
// the pragmatic option.
func isUnknownKidError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed to find key with key ID")
}

// Verify returns the validated subject (kcSub). azp is never treated as an audience fallback
// (it would widen the accepted-token set). On a kid the cached JWKS doesn't recognize — the
// signal a key rotation just happened at the IdP — Verify refetches ONCE and retries the parse
// before giving up. Any other failure (expired, bad signature, wrong issuer/audience) is never
// retried.
func (v *TokenVerifier) Verify(ctx context.Context, bearerToken string) (string, error) {
	if bearerToken == "" {
		return "", v.errInval
	}
	token, err := jwt.Parse([]byte(bearerToken),
		jwt.WithKeySet(v.currentSet()),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
	)
	if err != nil && isUnknownKidError(err) {
		if refreshErr := v.Refresh(ctx); refreshErr == nil {
			token, err = jwt.Parse([]byte(bearerToken),
				jwt.WithKeySet(v.currentSet()),
				jwt.WithValidate(true),
				jwt.WithIssuer(v.issuer),
				jwt.WithAudience(v.audience),
			)
		}
	}
	if err != nil {
		return "", v.errInval
	}
	sub, ok := token.Subject()
	if !ok || sub == "" {
		return "", v.errInval
	}
	return sub, nil
}
