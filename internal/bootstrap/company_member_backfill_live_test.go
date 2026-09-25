// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestSeed_CompanyMemberBackfill_ActiveMembersIdempotent proves SeedStep's company member
// backfill grants `company:<companyId>#member @ member:<memberId>#mapped_user` for every ACTIVE
// member (never an inactive one), exactly once — a second SeedStep run writes zero tuples and
// zero grant_ledger rows.
func TestSeed_CompanyMemberBackfill_ActiveMembersIdempotent(t *testing.T) {
	orgPool := bootstrapServicePool(t, "kiban_org", bootstrapTestEnv(t, "KIBAN_ORG_DB_PASSWORD"))
	adminPool := bootstrapServicePool(t, "kiban", bootstrapTestEnv(t, "KIBAN_DB_PASSWORD"))
	ctx := context.Background()

	companyID := uuid.New().String()
	memberIDs := []string{uuid.New().String(), uuid.New().String()}
	inactiveID := uuid.New().String()

	t.Cleanup(func() {
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company' AND object_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company' AND object_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.member WHERE company_id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)
	})

	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'CMBF', 'Backfill Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	for i, id := range memberIDs {
		if _, err := adminPool.Exec(ctx, `
			INSERT INTO org.member (id, company_id, code, display_name, is_active) VALUES ($1, $2, $3, 'Backfill Member', true)`,
			id, companyID, "CMBF"+string(rune('A'+i))); err != nil {
			t.Fatalf("insert member fixture: %v", err)
		}
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.member (id, company_id, code, display_name, is_active) VALUES ($1, $2, 'CMBFX', 'Inactive Member', false)`,
		inactiveID, companyID); err != nil {
		t.Fatalf("insert inactive member fixture: %v", err)
	}

	tupleCount := func(memberID string) int {
		var c int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='company' AND object_id=$1 AND relation='member'
			  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
			companyID, memberID,
		).Scan(&c); err != nil {
			t.Fatalf("query tuple: %v", err)
		}
		return c
	}
	ledgerCount := func() int {
		var c int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.grant_ledger WHERE object_type='company' AND object_id=$1 AND op='grant'`,
			companyID,
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
	for _, id := range memberIDs {
		if tupleCount(id) != 1 {
			t.Fatalf("first run: member %s tuple count = %d, want 1", id, tupleCount(id))
		}
	}
	if tupleCount(inactiveID) != 0 {
		t.Fatal("first run: inactive member must not be backfilled")
	}
	if got := ledgerCount(); got != 2 {
		t.Fatalf("first run: grant_ledger rows = %d, want 2 (one per tuple written)", got)
	}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("second SeedStep.Run: %v", err)
	}
	for _, id := range memberIDs {
		if tupleCount(id) != 1 {
			t.Fatalf("second run: member %s tuple count = %d, want 1", id, tupleCount(id))
		}
	}
	if got := ledgerCount(); got != 2 {
		t.Fatalf("second run: grant_ledger rows = %d, want 2 (converged re-run writes nothing)", got)
	}
}
