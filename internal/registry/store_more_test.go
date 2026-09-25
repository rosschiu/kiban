// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/audit"
)

// TestCheckMigrationsApplied_Success proves the happy path against the real, already-migrated
// dev-stack schema (no fixture reset needed — schema_version_registry is DDL state, not row
// data resetRegistryFixtures touches).
func TestCheckMigrationsApplied_Success(t *testing.T) {
	pool := adminPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("unexpected error against a migrated schema: %v", err)
	}
}

// TestCheckMigrationsApplied_QueryError proves the actionable-error wrapping branch: a canceled
// context makes the underlying QueryRow fail without needing to touch real migration state
// (CheckMigrationsApplied never mutates schema itself, so a deliberately-broken schema isn't an
// option here anyway).
func TestCheckMigrationsApplied_QueryError(t *testing.T) {
	pool := adminPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := CheckMigrationsApplied(ctx, pool)
	if err == nil {
		t.Fatal("expected an error from a canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}

// TestStore_SetEnabled_EnableUnknownModule_NotFound proves the enable path's own ErrModuleNotFound
// branch (distinct from the disable path's mandatory-check branch already covered elsewhere):
// enabling a module with no installation row hits SetModuleEnabled's pgx.ErrNoRows directly,
// since enable never runs the disable-only catalog/mandatory lookup first.
func TestStore_SetEnabled_EnableUnknownModule_NotFound(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false) // catalog row exists, but NO installation row

	store := NewStore(registryPool(t))
	_, err := store.SetEnabled(context.Background(), "alpha", true, nil)
	if !errors.Is(err, ErrModuleNotFound) {
		t.Errorf("err = %v, want ErrModuleNotFound", err)
	}
}

// TestStore_SetEnabled_DisableUnknownModule_NotFound covers the disable path's OWN
// GetModuleCatalogEntry ErrNoRows branch (module_key absent from the catalog entirely).
func TestStore_SetEnabled_DisableUnknownModule_NotFound(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	_, err := store.SetEnabled(context.Background(), "ghost", false, nil)
	if !errors.Is(err, ErrModuleNotFound) {
		t.Errorf("err = %v, want ErrModuleNotFound", err)
	}
}

// TestStore_SetEnabled_EnableSuccess_NoAuditRecord proves the full happy-path commit with a nil
// auditRecord callback (http.go always passes one, but the store API itself supports nil —
// exercised directly here).
func TestStore_SetEnabled_EnableSuccess_NoAuditRecord(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)

	store := NewStore(registryPool(t))
	result, err := store.SetEnabled(context.Background(), "alpha", true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Enabled {
		t.Errorf("result.Enabled = false, want true")
	}
}

// TestStore_SetEnabled_DisableSuccess_WithAuditRecord proves auditRecord is invoked with the
// SAME open transaction — a row it writes via the tx (using the real audit.Writer, exactly as
// http.go does) commits together with the enable/disable mutation — and that a non-mandatory
// disable succeeds.
func TestStore_SetEnabled_DisableSuccess_WithAuditRecord(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, true)

	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}

	store := NewStore(registryPool(t))
	called := false
	result, err := store.SetEnabled(context.Background(), "alpha", false, func(ctx context.Context, tx pgx.Tx) error {
		called = true
		return auditWriter.Record(ctx, tx, audit.Event{
			Actor:   "test",
			Action:  "platform.module.disable",
			Subject: "module:alpha",
			Payload: map[string]any{"enabled": false},
		})
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("auditRecord callback was never invoked")
	}
	if result.Enabled {
		t.Errorf("result.Enabled = true, want false")
	}

	var count int
	if err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.registry__events
		WHERE subject = 'module:alpha' AND action = 'platform.module.disable'
	`).Scan(&count); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Errorf("audit rows = %d, want 1 (proves auditRecord ran inside the same committed tx)", count)
	}
}

// TestStore_SetEnabled_AuditRecordError_RollsBack proves a failing auditRecord aborts the whole
// mutation: the enable/disable change must not be visible after the transaction rolls back.
func TestStore_SetEnabled_AuditRecordError_RollsBack(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)

	store := NewStore(registryPool(t))
	sentinel := errors.New("boom")
	_, err := store.SetEnabled(context.Background(), "alpha", true, func(ctx context.Context, tx pgx.Tx) error {
		return sentinel
	})
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the auditRecord sentinel error", err)
	}

	cap, _, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("capability lookup: %v", err)
	}
	if cap.Enabled {
		t.Errorf("module was enabled despite the auditRecord failure (transaction did not roll back): %+v", cap)
	}
}

// TestStore_SetEnabled_EnableNotInstalled_Refused proves the not-installed guard: enabling a module whose
// installation row has installed=false is refused with ErrModuleNotInstalled and nothing is
// written — the row is unchanged, the module's fragment stays inactive, no default-grant tuple
// appears for an active company, and no audit row is written.
func TestStore_SetEnabled_EnableNotInstalled_Refused(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	ctx := context.Background()

	companyID := uuid.New().String()
	if _, err := admin.Exec(ctx, `INSERT INTO org.org_unit (id, type_key, code, name, is_active) VALUES ($1, 'company', 'NOTINST', 'Not Installed Co', true)`, companyID); err != nil {
		t.Fatalf("insert company fixture: %v", err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, `DELETE FROM authz.default_grant WHERE company_id=$1`, companyID)                                          //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%")        //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type='company_module' AND object_id LIKE $1`, companyID+"/%") //nolint:errcheck
		admin.Exec(ctx, `DELETE FROM org.org_unit WHERE id=$1`, companyID)                                                         //nolint:errcheck
	})

	store := NewStore(registryPool(t))
	// Seed with the module absent from the installed set: catalog + installation row
	// (installed=false, enabled=false) + an inactive model_fragment row.
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(validFragment)},
	}
	if err := store.Seed(ctx, manifests, map[string]bool{}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	var installed, enabled bool
	if err := admin.QueryRow(ctx, `SELECT installed, enabled FROM platform.module_installation WHERE module_key='widget'`).Scan(&installed, &enabled); err != nil {
		t.Fatalf("read installation precondition: %v", err)
	}
	if installed || enabled {
		t.Fatalf("precondition: installed=%v enabled=%v, want false/false", installed, enabled)
	}

	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	_, err = store.SetEnabled(ctx, "widget", true, func(ctx context.Context, tx pgx.Tx) error {
		return auditWriter.Record(ctx, tx, audit.Event{Actor: "test", Action: "platform.module.enable", Subject: "module:widget"})
	})
	if !errors.Is(err, ErrModuleNotInstalled) {
		t.Fatalf("err = %v, want ErrModuleNotInstalled", err)
	}

	if err := admin.QueryRow(ctx, `SELECT installed, enabled FROM platform.module_installation WHERE module_key='widget'`).Scan(&installed, &enabled); err != nil {
		t.Fatalf("read installation: %v", err)
	}
	if installed || enabled {
		t.Errorf("installation row changed: installed=%v enabled=%v, want false/false", installed, enabled)
	}
	if _, active, found := getModelFragment(t, admin, "widget"); !found || active {
		t.Errorf("model_fragment found=%v active=%v, want found and inactive", found, active)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, companyID+"/widget").Scan(&count); err != nil {
		t.Fatalf("query tuple: %v", err)
	}
	if count != 0 {
		t.Errorf("company_module tuple count = %d, want 0 (no default grant on a refused enable)", count)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit.registry__events WHERE subject='module:widget'`).Scan(&count); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if count != 0 {
		t.Errorf("audit row count = %d, want 0 (nothing committed on a refused enable)", count)
	}
}
