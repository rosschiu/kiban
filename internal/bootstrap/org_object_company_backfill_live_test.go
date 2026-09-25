// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestSeed_OrgObjectCompanyBackfill_Idempotent proves SeedStep's position/group company
// backfill grants `position:<id>#company @ company:<c>` and `group:<id>#company @ company:<c>`
// for pre-existing rows exactly once — a second SeedStep run writes zero tuples and zero
// grant_ledger rows.
func TestSeed_OrgObjectCompanyBackfill_Idempotent(t *testing.T) {
	orgPool := bootstrapServicePool(t, "kiban_org", bootstrapTestEnv(t, "KIBAN_ORG_DB_PASSWORD"))
	adminPool := bootstrapServicePool(t, "kiban", bootstrapTestEnv(t, "KIBAN_DB_PASSWORD"))
	ctx := context.Background()

	companyID := uuid.New().String()
	positionID := uuid.New().String()
	groupID := uuid.New().String()

	t.Cleanup(func() {
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id IN ($1, $2)`, positionID, groupID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_id IN ($1, $2)`, positionID, groupID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.position WHERE id=$1`, positionID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org."group" WHERE id=$1`, groupID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)
	})

	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'OOBF', 'Backfill Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	// Raw rows, deliberately WITHOUT the anchor org.Store.CreatePosition/CreateGroup would write:
	// exactly the pre-anchor state the backfill exists for.
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.position (id, company_id, code, title, org_unit_id) VALUES ($1, $2, 'OOBF-POS', 'Backfill Position', $2)`,
		positionID, companyID); err != nil {
		t.Fatalf("insert position fixture: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org."group" (id, company_id, code, name, source) VALUES ($1, $2, 'OOBF-GRP', 'Backfill Group', 'kiban')`,
		groupID, companyID); err != nil {
		t.Fatalf("insert group fixture: %v", err)
	}

	tupleCount := func(objType, id string) int {
		var c int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type=$1 AND object_id=$2 AND relation='company'
			  AND subject_type='company' AND subject_id=$3 AND subject_relation=''`,
			objType, id, companyID,
		).Scan(&c); err != nil {
			t.Fatalf("query tuple: %v", err)
		}
		return c
	}
	ledgerCount := func() int {
		var c int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.grant_ledger WHERE object_id IN ($1, $2) AND relation='company' AND op='grant'`,
			positionID, groupID,
		).Scan(&c); err != nil {
			t.Fatalf("query grant_ledger: %v", err)
		}
		return c
	}

	deps := &Deps{OrgPool: orgPool}
	step := SeedStep{}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("first SeedStep.Run: %v", err)
	}
	if tupleCount("position", positionID) != 1 || tupleCount("group", groupID) != 1 {
		t.Fatalf("first run: position/group tuple counts = %d/%d, want 1/1", tupleCount("position", positionID), tupleCount("group", groupID))
	}
	if got := ledgerCount(); got != 2 {
		t.Fatalf("first run: grant_ledger rows = %d, want 2 (one per tuple written)", got)
	}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("second SeedStep.Run: %v", err)
	}
	if tupleCount("position", positionID) != 1 || tupleCount("group", groupID) != 1 {
		t.Fatal("second run: tuples duplicated")
	}
	if got := ledgerCount(); got != 2 {
		t.Fatalf("second run: grant_ledger rows = %d, want still 2 (converged rerun writes nothing)", got)
	}
}
