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

// TestSeed_DefaultGrantBackfill_ExistingPairsAndNonResurrection proves SeedStep's own
// default-grant backfill grants `company_module:<companyId>/<moduleKey>#system @
// system:platform` for every (active company x installed+enabled module) pair it finds, exactly
// once — a second SeedStep run never duplicates it, and after the tuple is deliberately deleted
// (the exclusion the product requires), a THIRD SeedStep run never resurrects it.
func TestSeed_DefaultGrantBackfill_ExistingPairsAndNonResurrection(t *testing.T) {
	registryPool := bootstrapServicePool(t, "kiban_registry", bootstrapTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	adminPool := bootstrapServicePool(t, "kiban", bootstrapTestEnv(t, "KIBAN_DB_PASSWORD"))
	ctx := context.Background()

	moduleKey := fmt.Sprintf("abf%d", time.Now().UnixNano()%1000000)
	companyID := uuid.New().String()

	t.Cleanup(func() {
		// moduleKey is unique per test run (time-suffixed) and DefaultGrantBackfill enumerates
		// EVERY active company against it, not just this fixture's own companyID — clean up by
		// moduleKey across all companies, not just this one, so no other active company (incl.
		// real ones in a shared kiban-test stack) is left with an orphaned default_grant/tuple
		// row for a module_installation row this test is about to delete.
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.default_grant WHERE module_key=$1`, moduleKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM platform.module_installation WHERE module_key=$1`, moduleKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM platform.module_catalog WHERE module_key=$1`, moduleKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)
	})

	if _, err := adminPool.Exec(ctx, `
		INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'ABFCO', 'Backfill Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO platform.module_catalog (module_key, display_name, scope_type, base_path, health_path, port, license_class, manifest_version)
		VALUES ($1, 'Backfill Module', 'company', '/api/abf', '/health', 8398, 'foundation', '0.1.0')`, moduleKey); err != nil {
		t.Fatalf("insert module_catalog fixture: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
		INSERT INTO platform.module_installation (module_key, installed, enabled) VALUES ($1, true, true)`, moduleKey); err != nil {
		t.Fatalf("insert module_installation fixture: %v", err)
	}

	tupleExists := func() bool {
		var count int
		if err := adminPool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND subject_type='system' AND subject_id='platform'`,
			companyID+"/"+moduleKey,
		).Scan(&count); err != nil {
			t.Fatalf("query tuple: %v", err)
		}
		return count == 1
	}

	deps := &Deps{RegistryPool: registryPool, AuthzPool: authzPool}

	step := SeedStep{}
	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("first SeedStep.Run: %v", err)
	}
	if !tupleExists() {
		t.Fatal("first SeedStep run: expected the backfilled default company_module tuple to exist")
	}

	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("second SeedStep.Run: %v", err)
	}
	var ledgerCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*) FROM authz.grant_ledger WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND op='grant'`,
		companyID+"/"+moduleKey,
	).Scan(&ledgerCount); err != nil {
		t.Fatalf("query grant_ledger: %v", err)
	}
	if ledgerCount != 1 {
		t.Fatalf("grant_ledger grant-op count after second run = %d, want 1 (default-ONCE, no duplicate)", ledgerCount)
	}

	// Exclusion: delete the tuple (stand-in for the future revoke surface) and re-run SeedStep —
	// it must NOT come back.
	if _, err := adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, companyID+"/"+moduleKey); err != nil {
		t.Fatalf("delete tuple (simulate exclusion): %v", err)
	}
	if tupleExists() {
		t.Fatal("tuple still present immediately after delete — test fixture bug")
	}
	if _, _, err := step.Run(ctx, deps); err != nil {
		t.Fatalf("third SeedStep.Run (post-exclusion): %v", err)
	}
	if tupleExists() {
		t.Fatal("NON-RESURRECTION VIOLATED: SeedStep re-granted a deliberately-excluded default tuple")
	}
}
