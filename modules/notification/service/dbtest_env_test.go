// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/livestack"
)

// testLogger is a discard logger for worker tests that don't assert on log output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).
func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// newTestPool connects to the live Postgres as kiban_notification (the runtime role — migrations must
// already be applied via `make migrate-notification`).
func newTestPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_notification", testEnv(t, "KIBAN_NOTIFICATION_DB_PASSWORD"))
}

// testClaimGroup is this `go test` binary run's own delivery_job claim_group: every Store this
// package's tests build (newTestStore, below) is bound to it, so every delivery_job a test
// enqueues (SendMessage) or claims (ClaimJobs) is scoped to this one run — never the live
// kiban-notification compose container's worker (always "default"), and never a previous or
// concurrent `go test` invocation (random per process). This is what makes `go test
// ./modules/notification/...` deterministic against a live, running worker container, with no
// need to stop the notification container first.
var testClaimGroup = "test-" + uuid.NewString()

// newTestStore builds a Store bound to this run's testClaimGroup. Deliberately does NOT reset or
// delete any notification table: claim_group scoping already isolates this run's delivery_job
// rows from both the live container's ("default") and any other run's, and every other table
// (channel/message/subscription/recipient_state) is scoped by each test's own random companyID,
// so nothing here needs — or should — touch rows a live, running container may have created.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.notification__events")
	if err != nil {
		t.Fatalf("dbtest: audit writer: %v", err)
	}
	return NewStore(pool, auditWriter, testClaimGroup, NewWebhookPolicyFromEnv())
}

// deleteChannelCascade removes a channel and (via ON DELETE CASCADE) every subscription/
// message/recipient_state/delivery_job row it owns. Registered as t.Cleanup by any test that
// creates delivery_job rows (ClaimJobs is a global, not company-scoped, queue by design —
// The delivery design is one worker pool across every company — so a job left behind by one
// test IS visible to a later test's ClaimJobs call in the same `go test` run; tests that don't
// care about delivery jobs don't need this, since their own assertions are already scoped to
// their own random companyID).
func deleteChannelCascade(t *testing.T, store *Store, channelID uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM notification.channel WHERE id = $1`, pgFromUUID(channelID))
	})
}
