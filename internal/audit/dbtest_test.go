// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).
// audit.Writer's contract is "write inside the caller's transaction, against the real Postgres
// wire protocol" — Postgres is never mocked, so its in-transaction commit/rollback semantics are
// proven here against the real stack, reusing audit.identity__events (a real, already-migrated
// audit.<module>__<name> table, so this package needs no test-only table).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// adminPool connects as the migration-owner role (kiban) — the only role with rights to
// TRUNCATE audit.identity__events between tests.
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// identityPool connects as kiban_identity — the real runtime role that owns INSERT/SELECT on
// audit.identity__events — so Record's in-transaction proof runs with the actual
// grants a real Writer caller has.
func identityPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_identity", testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD"))
}

// resetAuditFixtures empties audit.identity__events. TRUNCATE is rejected at the storage level
// too (migrations/identity/0006), so this test-only reset steps around that trigger as the
// table owner and re-enables it in the same batch.
func resetAuditFixtures(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	if _, err := admin.Exec(context.Background(), `
		ALTER TABLE audit.identity__events DISABLE TRIGGER identity__events_reject_truncate;
		TRUNCATE TABLE audit.identity__events RESTART IDENTITY;
		ALTER TABLE audit.identity__events ENABLE TRIGGER identity__events_reject_truncate`); err != nil {
		t.Fatalf("dbtest: reset audit fixtures: %v", err)
	}
}
