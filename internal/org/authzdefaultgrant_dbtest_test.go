// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"
)

// TestCreateOrgUnit_NewCompanyDefaultGrantsEnabledModules proves the production hook:
// creating a COMPANY-typed org_unit (the real POST /internal/org/units path) grants every
// currently installed+enabled module's default company_module tuple, in the SAME transaction as
// the unit's own creation.
func TestCreateOrgUnit_NewCompanyDefaultGrantsEnabledModules(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	ctx := context.Background()

	const moduleKey = "dg_org_widget"
	if _, err := admin.Exec(ctx, `
		INSERT INTO platform.module_catalog (module_key, display_name, scope_type, base_path, health_path, port, license_class, manifest_version)
		VALUES ($1, 'Default Grant Org Widget', 'company', '/api/dg-org-widget', '/health', 8399, 'foundation', '0.1.0')
		ON CONFLICT (module_key) DO NOTHING`, moduleKey); err != nil {
		t.Fatalf("insert module_catalog fixture: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO platform.module_installation (module_key, installed, enabled) VALUES ($1, true, true)
		ON CONFLICT (module_key) DO UPDATE SET installed=true, enabled=true`, moduleKey); err != nil {
		t.Fatalf("insert module_installation fixture: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE module_key=$1`, moduleKey)                                          //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey)        //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, "%/"+moduleKey) //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM platform.module_installation WHERE module_key=$1`, moduleKey)                                 //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM platform.module_catalog WHERE module_key=$1`, moduleKey)                                      //nolint:errcheck
	})

	store := newTestStore(t)
	unit, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "DGORG", "Default Grant Org Co", true)
	if err != nil {
		t.Fatalf("CreateOrgUnit: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='system' AND subject_type='system' AND subject_id='platform'`,
		unit.ID.String()+"/"+moduleKey,
	).Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("company_module default tuple count = %d, want 1", count)
	}
	// The company anchor lands in the same transaction.
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='company' AND subject_type='company' AND subject_id=$2`,
		unit.ID.String()+"/"+moduleKey, unit.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("query anchor: %v", err)
	}
	if count != 1 {
		t.Fatalf("company_module#company anchor count = %d, want 1", count)
	}
}

// TestCreateOrgUnit_NonCompanyUnitGetsNoDefaultGrant proves the hook is company-scoped: creating
// a non-company org_unit (a taxonomy node) never writes any company_module default grant.
func TestCreateOrgUnit_NonCompanyUnitGetsNoDefaultGrant(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	ctx := context.Background()

	store := newTestStore(t)
	// A non-company unit must sit under a company (a root is always a company);
	// the parent company's own default grant is keyed by the parent's id, not this unit's.
	parent, err := store.CreateOrgUnit(ctx, "test-actor", "company", nil, "DGPAR", "Default Grant Parent Co", true)
	if err != nil {
		t.Fatalf("CreateOrgUnit(parent company): %v", err)
	}
	unit, err := store.CreateOrgUnit(ctx, "test-actor", "territory", &parent.ID, "DGTERR", "Default Grant Territory", true)
	if err != nil {
		t.Fatalf("CreateOrgUnit: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.default_grant WHERE company_id=$1`, unit.ID.String()).Scan(&count); err != nil {
		t.Fatalf("query default_grant: %v", err)
	}
	if count != 0 {
		t.Fatalf("default_grant count for a non-company unit = %d, want 0", count)
	}
}
