// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// bootstrapLockKey is the fixed pg_advisory_lock key every kiban-bootstrap run contends for —
// the advisory lock serializes concurrent runs. Arbitrary but FIXED, so
// every bootstrap binary (any version, any host) contends for the same lock rather than a
// per-process one.
const bootstrapLockKey int64 = 0x4B4942414E30 // arbitrary fixed constant ("KIBAN0"-ish), never derived per-run

// WithAdvisoryLock acquires a SESSION-level Postgres advisory lock (pg_advisory_lock) on a
// single dedicated connection, blocking until any concurrent bootstrap run releases it, runs
// fn, then releases the lock and the connection. Session-level advisory locks are tied to the
// connection that took them (Postgres semantics) — using one pinned pgxpool.Conn for both
// acquire and release, never released from a different connection, is load-bearing here, not
// incidental.
func WithAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, bootstrapLockKey); err != nil {
		return err
	}
	// Best-effort unlock: a background context so a caller-canceled ctx doesn't skip releasing
	// the lock a concurrent, still-running bootstrap is waiting on.
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, bootstrapLockKey) //nolint:errcheck

	return fn(ctx)
}
