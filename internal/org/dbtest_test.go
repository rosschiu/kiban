// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// adminPool connects as the migration-owner role (kiban) — used only to set up/tear down test
// fixtures the runtime role (kiban_org) has no DDL/cross-row-reset rights to perform.
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// orgPool connects as kiban_org — the real runtime role — so tests exercise the
// actual grants the service will run with in production.
func orgPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_org", testEnv(t, "KIBAN_ORG_DB_PASSWORD"))
}

// resetOrgFixtures wipes every org-owned table (and its audit table) plus any identity fixture
// rows this package's tests created, to a known-empty state, restoring org_unit_type's seed
// rows migration 0002 inserts.
func resetOrgFixtures(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	// The audit tables reject TRUNCATE at the storage level (migrations org/0011, identity/0006);
	// this fixture reset is the one place the trigger is stepped around — as the table owner,
	// test-only, re-enabled in the same statement batch.
	_, err := admin.Exec(ctx, `
		ALTER TABLE audit.org__events DISABLE TRIGGER org__events_reject_truncate;
		ALTER TABLE audit.identity__events DISABLE TRIGGER identity__events_reject_truncate;
		TRUNCATE TABLE org.group_member, org.group, org.position_assignment, org.position, org.member, org.org_unit, audit.org__events RESTART IDENTITY CASCADE;
		TRUNCATE TABLE identity.mfa_policy, identity.user_login_observation,
			identity.user_account, audit.identity__events RESTART IDENTITY CASCADE;
		ALTER TABLE audit.org__events ENABLE TRIGGER org__events_reject_truncate;
		ALTER TABLE audit.identity__events ENABLE TRIGGER identity__events_reject_truncate;
		INSERT INTO identity.mfa_policy (scope, subject_id, required, method) VALUES ('global', NULL, false, NULL);
		-- LinkUser/UnlinkUser/AssignNow/EndAssignment and group membership writes create
		-- authz.tuple/authz.grant_ledger rows (position:*#holder, member:*#mapped_user,
		-- group:*#member). Clean them with a scoped DELETE, never a blanket TRUNCATE of
		-- authz.tuple: other packages' tests and bootstrap's structural and default-grant tuples
		-- share this database and must survive.
		DELETE FROM authz.tuple WHERE object_type IN ('position', 'member', 'group') OR subject_type IN ('position', 'member', 'group');
		DELETE FROM authz.grant_ledger WHERE object_type IN ('position', 'member', 'group') OR subject_type IN ('position', 'member', 'group');
	`)
	if err != nil {
		t.Fatalf("dbtest: reset fixtures: %v", err)
	}
}

// newTestStore builds a Store against the real kiban_org role and an audit writer for
// "audit.org__events".
func newTestStore(t *testing.T) *Store {
	t.Helper()
	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	return NewStore(orgPool(t), auditWriter)
}
