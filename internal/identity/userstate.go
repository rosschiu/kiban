// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserStateSource answers "is this Keycloak user enabled" for the decision's step 2. Two
// implementations: KCDBReader reads Keycloak's own table (the default when Keycloak shares the
// Postgres server, docs/operating.md), AdminClient asks the admin REST API (the fallback,
// wrapped in CachedUserState). Both answer the KCState tri-state and never default to enabled.
type UserStateSource interface {
	UserEnabled(ctx context.Context, kcSub string) (string, error)
}

// KCDBReader reads `user_entity.enabled` straight from Keycloak's database: one indexed SELECT
// per decision, no copy, no lag. It is a deliberate coupling to one column of Keycloak's
// schema; NewKCDBReader asserts the shape at start-up so a schema change fails loudly.
type KCDBReader struct {
	pool  *pgxpool.Pool
	realm string
}

const kcUserEnabledSQL = `
SELECT u.enabled FROM user_entity u JOIN realm r ON r.id = u.realm_id
WHERE u.id = $1 AND r.name = $2`

// NewKCDBReader probes the two tables and columns the reader depends on and refuses anything
// else, so an unexpected Keycloak schema is a start-up failure, never a silent allow.
func NewKCDBReader(ctx context.Context, pool *pgxpool.Pool, realm string) (*KCDBReader, error) {
	var realmID string
	err := pool.QueryRow(ctx, `SELECT r.id FROM realm r LEFT JOIN user_entity u ON false WHERE r.name = $1`, realm).Scan(&realmID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("identity: keycloak database: realm %q not found", realm)
	}
	if err != nil {
		return nil, fmt.Errorf("identity: keycloak database probe (realm, user_entity): %w", err)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM user_entity WHERE false UNION ALL SELECT true`).Scan(&enabled); err != nil {
		return nil, fmt.Errorf("identity: keycloak database probe (user_entity.enabled): %w", err)
	}
	return &KCDBReader{pool: pool, realm: realm}, nil
}

// UserEnabled returns KCStateTrue/False from the row, or KCStateUnknown (with the error for
// logging) when the user is absent from the realm or the query fails.
func (r *KCDBReader) UserEnabled(ctx context.Context, kcSub string) (string, error) {
	var enabled bool
	err := r.pool.QueryRow(ctx, kcUserEnabledSQL, kcSub, r.realm).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return KCStateUnknown, fmt.Errorf("identity: keycloak user %s not in realm %s", kcSub, r.realm)
	}
	if err != nil {
		return KCStateUnknown, fmt.Errorf("identity: keycloak user read: %w", err)
	}
	if enabled {
		return KCStateTrue, nil
	}
	return KCStateFalse, nil
}

// CachedUserState remembers a definite answer (true or false, never unknown) for ttl, so the
// admin API fallback is not called on every decision. A disable is seen within ttl.
type CachedUserState struct {
	inner UserStateSource
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	seen  map[string]cachedState
}

type cachedState struct {
	state string
	until time.Time
}

// NewCachedUserState wraps inner; ttl <= 0 disables caching.
func NewCachedUserState(inner UserStateSource, ttl time.Duration) *CachedUserState {
	return &CachedUserState{inner: inner, ttl: ttl, now: time.Now, seen: map[string]cachedState{}}
}

func (c *CachedUserState) UserEnabled(ctx context.Context, kcSub string) (string, error) {
	if c.ttl > 0 {
		c.mu.Lock()
		e, ok := c.seen[kcSub]
		c.mu.Unlock()
		if ok && c.now().Before(e.until) {
			return e.state, nil
		}
	}
	state, err := c.inner.UserEnabled(ctx, kcSub)
	if c.ttl > 0 && state != KCStateUnknown {
		c.mu.Lock()
		c.seen[kcSub] = cachedState{state: state, until: c.now().Add(c.ttl)}
		c.mu.Unlock()
	}
	return state, err
}
