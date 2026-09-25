// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/livestack"
	"github.com/rosschiu/kiban/internal/registry"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func gatewayTestEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// gatewayAdminPool connects as the migration-owner role (kiban) — used only to reset the
// registry's own test fixtures for TestProxy_ZeroEditModuleRouting (the gateway itself has no
// DB role at all — the gateway is stateless; this pool exists purely to drive
// internal/registry's real Store the same way internal/registry's own tests do).
func gatewayAdminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// gatewayRegistryPool connects as kiban_registry — the real registry runtime role.
func gatewayRegistryPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_registry", gatewayTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
}

// resetGatewayRegistryFixtures wipes the registry's own tables to a known-empty state before
// TestProxy_ZeroEditModuleRouting runs (same shape as internal/registry's own
// resetRegistryFixtures — duplicated locally rather than imported, since it's unexported there).
func resetGatewayRegistryFixtures(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	t.Cleanup(func() {
		if err := registry.SeedBuiltin(context.Background(), admin); err != nil {
			t.Errorf("dbtest: reseed built-in modules: %v", err)
		}
	})
	_, err := admin.Exec(context.Background(), `
		ALTER TABLE audit.registry__events DISABLE TRIGGER registry__events_reject_truncate;
		TRUNCATE TABLE platform.module_dependency, platform.module_installation,
			platform.module_catalog, audit.registry__events RESTART IDENTITY CASCADE;
		ALTER TABLE audit.registry__events ENABLE TRIGGER registry__events_reject_truncate;
	`)
	if err != nil {
		t.Fatalf("dbtest: reset registry fixtures: %v", err)
	}
}

// gatewayTestAuditWriter builds the audit writer TestProxy_ZeroEditModuleRouting's embedded
// registry.Service needs (same table cmd/registry/main.go uses).
func gatewayTestAuditWriter(t *testing.T) *audit.Writer {
	t.Helper()
	w, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	return w
}
