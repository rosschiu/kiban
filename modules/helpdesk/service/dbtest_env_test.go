// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).
func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// newTestPool connects to the live Postgres as kiban_helpdesk (the runtime role — migrations must
// already be applied via `make migrate-helpdesk`).
func newTestPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_helpdesk", testEnv(t, "KIBAN_HELPDESK_DB_PASSWORD"))
}

// newTestStore builds a Store against the live test pool. Every document/share row this
// package's tests create is scoped by its own random companyID/docID, so nothing here needs to
// truncate any table shared with a running compose container.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.helpdesk__events")
	if err != nil {
		t.Fatalf("dbtest: audit writer: %v", err)
	}
	return NewStore(pool, auditWriter)
}
