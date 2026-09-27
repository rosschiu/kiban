// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// adminPool connects as the migration-owner role (kiban) — used only to set up/tear down test
// fixtures the runtime role (kiban_registry) has no DDL/cross-row-reset rights to perform.
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// registryPool connects as kiban_registry — the real runtime role — so tests exercise
// the actual grants the service will run with in production.
func registryPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_registry", testEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
}

// resetRegistryFixtures wipes every registry-owned table to a known-empty state (admin
// connection — the runtime role has no DELETE-everything shortcut it should ever need in
// production, so tests deliberately use the higher-privileged connection for this).
func resetRegistryFixtures(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	// The shared test stack's registry container seeds its catalog only at boot; put the
	// built-in modules back the way that boot did so the stack stays usable after this test.
	t.Cleanup(func() {
		if err := SeedBuiltin(context.Background(), admin); err != nil {
			t.Errorf("dbtest: reseed built-in modules: %v", err)
		}
	})
	_, err := admin.Exec(ctx, `
		ALTER TABLE audit.registry__events DISABLE TRIGGER registry__events_reject_truncate;
		TRUNCATE TABLE platform.module_dependency, platform.module_installation,
			platform.module_catalog, audit.registry__events, authz.model_fragment RESTART IDENTITY CASCADE;
		ALTER TABLE audit.registry__events ENABLE TRIGGER registry__events_reject_truncate;
	`)
	if err != nil {
		t.Fatalf("dbtest: reset fixtures: %v", err)
	}
}

// getModelFragment reads back one authz.model_fragment row (admin connection — test assertion
// only, never how the runtime code itself reads this table).
func getModelFragment(t *testing.T, admin *pgxpool.Pool, moduleKey string) (fragment []byte, active bool, found bool) {
	t.Helper()
	err := admin.QueryRow(context.Background(),
		`SELECT fragment, active FROM authz.model_fragment WHERE module_key = $1`, moduleKey,
	).Scan(&fragment, &active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, false
		}
		t.Fatalf("dbtest: read model_fragment %q: %v", moduleKey, err)
	}
	return fragment, active, true
}

// insertCatalogFixture inserts a minimal catalog row directly (bypassing Store.Capability's own
// upsert path, so capability tests are decoupled from the seed/upsert logic under test
// elsewhere).
func insertCatalogFixture(t *testing.T, admin *pgxpool.Pool, moduleKey string, mandatory bool) {
	t.Helper()
	_, err := admin.Exec(context.Background(), `
		INSERT INTO platform.module_catalog
			(module_key, display_name, scope_type, mandatory, base_path, health_path, port, license_class, manifest_version, is_active)
		VALUES ($1, $1, 'company', $2, '/api/'||$1, '/health', 8100, 'foundation', '0.1.0', true)
	`, moduleKey, mandatory)
	if err != nil {
		t.Fatalf("dbtest: insert catalog fixture %s: %v", moduleKey, err)
	}
}

func insertInstallationFixture(t *testing.T, admin *pgxpool.Pool, moduleKey string, installed, enabled bool) {
	t.Helper()
	_, err := admin.Exec(context.Background(), `
		INSERT INTO platform.module_installation (module_key, installed, enabled) VALUES ($1, $2, $3)
	`, moduleKey, installed, enabled)
	if err != nil {
		t.Fatalf("dbtest: insert installation fixture %s: %v", moduleKey, err)
	}
}

func insertDependencyFixture(t *testing.T, admin *pgxpool.Pool, moduleKey, dependsOn string) {
	t.Helper()
	_, err := admin.Exec(context.Background(), `
		INSERT INTO platform.module_dependency (module_key, depends_on_module_key, version_range)
		VALUES ($1, $2, '>=0.0.0')
	`, moduleKey, dependsOn)
	if err != nil {
		t.Fatalf("dbtest: insert dependency fixture %s -> %s: %v", moduleKey, dependsOn, err)
	}
}
