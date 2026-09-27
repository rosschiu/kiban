// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The company-typed org_unit fixture below is inserted directly (registry's own test suite
// doesn't import internal/org) — org.org_unit_type.key='company' is pre-seeded permanently by
// migrations/org/0002_org_tables.sql, never truncated by any reset helper.

// TestSeed_DefaultGrantsInstalledEnabledModuleForActiveCompanies proves Seed's default-grant hook:
// an installed+enabled module (with or without an authz fragment) gets its default company_module
// tuple written for every currently active company.
func TestSeed_DefaultGrantsInstalledEnabledModuleForActiveCompanies(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	ctx := context.Background()

	companyID := uuid.New().String()
	if _, err := admin.Exec(ctx, `INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'DGREG', 'Default Grant Registry Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE company_id=$1`, companyID)                                          //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%")        //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%") //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)                                                         //nolint:errcheck
	})

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0"},
	}
	if err := store.Seed(ctx, manifests, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND subject_type='system' AND subject_id='platform'`,
		companyID+"/widget",
	).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("company_module default tuple count = %d, want 1", count)
	}

	// Re-running Seed must not duplicate the grant (default-ONCE).
	if err := store.Seed(ctx, manifests, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("Seed (rerun): %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1 AND relation='system'`, companyID+"/widget").Scan(&count); err != nil {
		t.Fatalf("query tuple after rerun: %v", err)
	}
	if count != 1 {
		t.Fatalf("company_module default tuple count after rerun = %d, want still 1", count)
	}
	// The company anchor rides along: exactly one after the rerun, never duplicated.
	if got := companyModuleAnchorCount(t, admin, companyID, "widget"); got != 1 {
		t.Fatalf("company_module#company anchor count after rerun = %d, want 1", got)
	}
}

// companyModuleAnchorCount counts `company_module:<c>/<m>#company @ company:<c>` rows.
func companyModuleAnchorCount(t *testing.T, admin *pgxpool.Pool, companyID, moduleKey string) int {
	t.Helper()
	var n int
	if err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='company' AND subject_type='company' AND subject_id=$2`,
		companyID+"/"+moduleKey, companyID).Scan(&n); err != nil {
		t.Fatalf("query anchor: %v", err)
	}
	return n
}

// TestSetEnabled_DefaultGrantsForActiveCompaniesOnEnable proves SetEnabled's default-grant hook:
// enabling a module via the admin API path grants its default company_module tuple for every
// active company, in the SAME transaction as the enable itself.
func TestSetEnabled_DefaultGrantsForActiveCompaniesOnEnable(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	ctx := context.Background()

	companyID := uuid.New().String()
	if _, err := admin.Exec(ctx, `INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'DGSET', 'Default Grant SetEnabled Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE company_id=$1`, companyID)                                          //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%")        //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%") //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)                                                         //nolint:errcheck
	})

	store := NewStore(registryPool(t))
	// Seed the module installed but NOT enabled first (mirrors a real "install then later
	// enable via admin API" sequence).
	manifests := []ModuleManifest{
		{ModuleKey: "gadget", DisplayName: "Gadget", ScopeType: "company", BasePath: "/api/gadget",
			HealthPath: "/health", Port: 8301, LicenseClass: "foundation", ManifestVersion: "0.1.0"},
	}
	if err := store.Seed(ctx, manifests, map[string]bool{}); err != nil {
		t.Fatalf("Seed (install-only): %v", err)
	}
	// Seed with an empty installed set leaves installed=false; SetEnabled refuses to enable such a row,
	// and no runtime install path exists yet — mark it installed directly.
	if _, err := admin.Exec(ctx, `UPDATE platform.module_installation SET installed=true WHERE module_key='gadget'`); err != nil {
		t.Fatalf("mark gadget installed: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, companyID+"/gadget").Scan(&count); err != nil {
		t.Fatalf("query tuple pre-enable: %v", err)
	}
	if count != 0 {
		t.Fatalf("company_module tuple count pre-enable = %d, want 0 (module not yet enabled)", count)
	}

	if _, err := store.SetEnabled(ctx, "gadget", true, nil); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1 AND relation='system'`, companyID+"/gadget").Scan(&count); err != nil {
		t.Fatalf("query tuple post-enable: %v", err)
	}
	if count != 1 {
		t.Fatalf("company_module tuple count post-enable = %d, want 1", count)
	}
	if got := companyModuleAnchorCount(t, admin, companyID, "gadget"); got != 1 {
		t.Fatalf("company_module#company anchor count post-enable = %d, want 1", got)
	}
	// Toggling off and on again must not duplicate the anchor.
	if _, err := store.SetEnabled(ctx, "gadget", false, nil); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if _, err := store.SetEnabled(ctx, "gadget", true, nil); err != nil {
		t.Fatalf("SetEnabled(true) rerun: %v", err)
	}
	if got := companyModuleAnchorCount(t, admin, companyID, "gadget"); got != 1 {
		t.Fatalf("company_module#company anchor count after re-enable = %d, want still 1", got)
	}
}
