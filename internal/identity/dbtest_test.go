// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// adminPool connects as the migration-owner role (kiban) — used only to set up/tear down test
// fixtures the runtime role (kiban_identity) has no DDL/cross-row-reset rights to perform.
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// identityPool connects as kiban_identity — the real runtime role — so tests exercise
// the actual grants the service will run with in production.
func identityPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_identity", testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD"))
}

// resetIdentityFixtures wipes every identity-owned table (and its audit table) to a known-empty
// state, restoring the single global mfa_policy row Seed migration 0002 inserts.
func resetIdentityFixtures(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := admin.Exec(ctx, `
		ALTER TABLE audit.identity__events DISABLE TRIGGER identity__events_reject_truncate;
		TRUNCATE TABLE identity.mfa_policy, identity.user_login_observation,
			identity.user_account, audit.identity__events RESTART IDENTITY CASCADE;
		ALTER TABLE audit.identity__events ENABLE TRIGGER identity__events_reject_truncate;
		INSERT INTO identity.mfa_policy (scope, subject_id, required, method) VALUES ('global', NULL, false, NULL);
	`)
	if err != nil {
		t.Fatalf("dbtest: reset fixtures: %v", err)
	}
}
