// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func testManifests() []ModuleManifest {
	return []ModuleManifest{
		{
			ModuleKey: "alpha", DisplayName: "Alpha", ScopeType: "company", Mandatory: false,
			BasePath: "/api/alpha", HealthPath: "/health", Port: 8201,
			LicenseClass: "foundation", ManifestVersion: "0.1.0",
		},
		{
			ModuleKey: "spine", DisplayName: "Spine", ScopeType: "global", Mandatory: true,
			BasePath: "/api/spine", HealthPath: "/health", Port: 8202,
			LicenseClass: "foundation", ManifestVersion: "0.1.0",
		},
	}
}

func TestParseInstalledModules_UnknownKeyFailsLoudly(t *testing.T) {
	_, err := ParseInstalledModules("alpha,ghost", testManifests())
	if err == nil {
		t.Fatal("expected an error for the unknown module key \"ghost\"")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the unknown key, got: %v", err)
	}
}

func TestParseInstalledModules_MandatoryAlwaysUnioned(t *testing.T) {
	installed, err := ParseInstalledModules("", testManifests())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !installed["spine"] {
		t.Errorf("mandatory module \"spine\" must be in the installed set even with an empty CSV")
	}
	if installed["alpha"] {
		t.Errorf("non-mandatory module \"alpha\" must not be installed when absent from the CSV")
	}
}

func TestParseInstalledModules_CSVUnion(t *testing.T) {
	installed, err := ParseInstalledModules(" alpha , spine ", testManifests())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !installed["alpha"] || !installed["spine"] {
		t.Errorf("installed = %v, want both alpha and spine", installed)
	}
}

// TestSeed_DisableThenRestart proves an operator disable via direct SQL survives a
// re-seed with the SAME env manifest — the seed never overwrites existing installed/enabled.
func TestSeed_DisableThenRestart(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	store := NewStore(registryPool(t))
	ctx := context.Background()

	manifests := testManifests()
	installed, err := ParseInstalledModules("alpha,spine", manifests)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := store.Seed(ctx, manifests, installed); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	cap, _, err := store.Capability(ctx, "alpha")
	if err != nil {
		t.Fatalf("capability after first seed: %v", err)
	}
	if !cap.Installed || !cap.Enabled {
		t.Fatalf("cap after first seed = %+v, want installed+enabled", cap)
	}

	// Operator disables "alpha" directly (simulating an admin action, not a re-seed).
	if _, err := admin.Exec(ctx, `UPDATE platform.module_installation SET enabled = false WHERE module_key = 'alpha'`); err != nil {
		t.Fatalf("operator disable: %v", err)
	}

	// "Restart": seed runs again with the identical env manifest.
	if err := store.Seed(ctx, manifests, installed); err != nil {
		t.Fatalf("second seed (restart): %v", err)
	}

	cap, code, err := store.Capability(ctx, "alpha")
	if err != nil {
		t.Fatalf("capability after restart: %v", err)
	}
	if cap.Enabled {
		t.Fatalf("operator disable was overwritten by re-seed (operator state must survive re-seed): cap = %+v, code = %q", cap, code)
	}
}

// TestSeed_ConcurrentNoErrorNoDuplicate proves the multi-replica boot case: two seeds racing
// against the same env manifest succeed without error and leave exactly one installation row.
func TestSeed_ConcurrentNoErrorNoDuplicate(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	store := NewStore(registryPool(t))
	ctx := context.Background()

	manifests := testManifests()
	installed, err := ParseInstalledModules("alpha,spine", manifests)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Seed(ctx, manifests, installed)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent seed returned an error: %v", err)
		}
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM platform.module_installation WHERE module_key = 'alpha'`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("module_installation rows for alpha = %d, want exactly 1 (no duplicate)", count)
	}
}
