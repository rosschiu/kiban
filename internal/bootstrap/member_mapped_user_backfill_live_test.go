// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSeed_MemberMappedUserBackfill_ExistingLinksAndIdempotent proves SeedStep's member
// mapped_user backfill grants `member:<memberId>#mapped_user @ user:<kcSub>` for every member
// ALREADY linked to a user (a pre-existing org.member.user_id link written before the
// tuple-maintenance code path existed), exactly once — a second
// SeedStep run never duplicates the grant_ledger row.
func TestSeed_MemberMappedUserBackfill_ExistingLinksAndIdempotent(t *testing.T) {
	orgPool := bootstrapServicePool(t, "kiban_org", bootstrapTestEnv(t, "KIBAN_ORG_DB_PASSWORD"))
	adminPool := bootstrapServicePool(t, "kiban", bootstrapTestEnv(t, "KIBAN_DB_PASSWORD"))
	ctx := context.Background()

	kcSub := fmt.Sprintf("mmbf-%d", time.Now().UnixNano()%1000000)
	companyID := uuid.New().String()
	userID := uuid.New().String()
	memberID := uuid.New().String()

	t.Cleanup(func() {
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='member' AND object_id=$1`, memberID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='member' AND object_id=$1`, memberID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.member WHERE id=$1`, memberID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)
		_, _ = adminPool.Exec(ctx, `DELETE FROM identity.user_account WHERE id=$1`, userID)
	})

	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'MMBFCO', 'Backfill Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO identity.user_account (id, kc_sub, email, preferred_username, lifecycle) VALUES ($1, $2, $2||'@example.com', $2, 'active')`,
		userID, kcSub); err != nil {
		t.Fatalf("insert identity user fixture: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.member (id, company_id, code, display_name, user_id, is_active) VALUES ($1, $2, 'MMBFM', 'Backfill Member', $3, true)`,
		memberID, companyID, userID); err != nil {
		t.Fatalf("insert member fixture (pre-linked, as if from before this code path existed): %v", err)
	}

	tupleExists := func() bool {
		var count int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='member' AND object_id=$1 AND relation='mapped_user' AND subject_type='user' AND subject_id=$2 AND subject_relation=''`,
			memberID, kcSub,
		).Scan(&count); err != nil {
			t.Fatalf("query tuple: %v", err)
		}
		return count == 1
	}

	deps := &Deps{OrgPool: orgPool}
	step := SeedStep{}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("first SeedStep.Run: %v", err)
	}
	if !tupleExists() {
		t.Fatal("first SeedStep run: expected the backfilled member mapped_user tuple to exist")
	}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("second SeedStep.Run: %v", err)
	}
	var ledgerCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*) FROM authz.grant_ledger WHERE object_type='member' AND object_id=$1 AND op='grant'`,
		memberID,
	).Scan(&ledgerCount); err != nil {
		t.Fatalf("query grant_ledger: %v", err)
	}
	if ledgerCount != 1 {
		t.Fatalf("grant_ledger grant-op count after second run = %d, want 1 (idempotent, no duplicate)", ledgerCount)
	}
}
