// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/registry"
)

// TestSeed_RegistryCAP001_OperatorDisabledModuleSurvivesReBootstrap seeds a synthetic module
// (mirroring registry's own seed_test.go pattern — the real KnownModules list is empty, so a
// synthetic manifest is how this mechanism is exercised at the bootstrap-step level too),
// operator-disables it directly (simulating an admin turning it off), then re-runs SeedStep
// with the SAME manifest — the disabled row must survive, never re-enabled (seed-missing-only,
// never overwritten).
func TestSeed_RegistryCAP001_OperatorDisabledModuleSurvivesReBootstrap(t *testing.T) {
	registryPool := bootstrapServicePool(t, "kiban_registry", bootstrapTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
	adminPool := bootstrapServicePool(t, "kiban", bootstrapTestEnv(t, "KIBAN_DB_PASSWORD"))

	moduleKey := fmt.Sprintf("bootseed%d", time.Now().UnixNano()%1000000)
	synthetic := []registry.ModuleManifest{{
		ModuleKey: moduleKey, DisplayName: "Seed Test Module", ScopeType: "global",
		Mandatory: false, BasePath: "/api/" + moduleKey, HealthPath: "/health", Port: 9999,
		LicenseClass: "foundation", ManifestVersion: "1.0.0",
	}}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DELETE FROM platform.module_installation WHERE module_key = $1`, moduleKey)
		_, _ = adminPool.Exec(context.Background(), `DELETE FROM platform.module_catalog WHERE module_key = $1`, moduleKey)
	})

	origKnown := KnownModules
	KnownModules = synthetic
	t.Cleanup(func() { KnownModules = origKnown })

	deps := &Deps{RegistryPool: registryPool, InstalledModulesCSV: moduleKey}

	outcome, detail, err := SeedStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("first seed run failed: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("first seed run outcome = %s, want applied: %s", outcome, detail)
	}

	// Operator disables the module directly (simulating an admin action through registry's own
	// API — this test reaches into the DB only because no such HTTP surface is this test's
	// subject; SeedStep itself never does this).
	if _, err := adminPool.Exec(context.Background(),
		`UPDATE platform.module_installation SET enabled = false WHERE module_key = $1`, moduleKey,
	); err != nil {
		t.Fatalf("simulate operator-disable: %v", err)
	}

	outcome2, detail2, err := SeedStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("second seed run failed: %v (detail: %s)", err, detail2)
	}
	t.Logf("second seed run: outcome=%s detail=%s", outcome2, detail2)

	var enabled bool
	if err := registryPool.QueryRow(context.Background(),
		`SELECT enabled FROM platform.module_installation WHERE module_key = $1`, moduleKey,
	).Scan(&enabled); err != nil {
		t.Fatalf("read installation row: %v", err)
	}
	if enabled {
		t.Fatal("VIOLATED: operator-disabled module was re-enabled by re-bootstrap")
	}
}

// TestSeed_StructuralTuples_IdempotentWithPostWriteRecheck proves SeedStructuralTuples grants a
// synthetic tuple, re-checks it post-write, and converges (no duplicate insert, no error) on a
// second call with the same tuple — idempotent by natural key — even though production's
// StructuralTuples list is empty (see seed.go's own comment on why).
func TestSeed_StructuralTuples_IdempotentWithPostWriteRecheck(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	t.Cleanup(func() {
		_, _ = authzPool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'bootseed-%'`)
		_, _ = authzPool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'bootseed-%'`)
	})

	tp := store.Tuple{ObjectType: "system", ObjectID: "bootseed-kiban", Relation: "superadmin", SubjectType: "user", SubjectID: "bootseed-u1"}

	detail1, applied1, err := SeedStructuralTuples(context.Background(), authzPool, "bootstrap", []store.Tuple{tp})
	if err != nil {
		t.Fatalf("first grant failed: %v", err)
	}
	if !applied1 {
		t.Fatalf("first grant applied = false, want true: %s", detail1)
	}
	t.Logf("first: %s", detail1)

	var count int
	if err := authzPool.QueryRow(context.Background(),
		`SELECT count(*) FROM authz.tuple WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject_type=$4 AND subject_id=$5`,
		tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID,
	).Scan(&count); err != nil {
		t.Fatalf("verify tuple: %v", err)
	}
	if count != 1 {
		t.Fatalf("tuple count = %d, want 1", count)
	}

	detail2, applied2, err := SeedStructuralTuples(context.Background(), authzPool, "bootstrap", []store.Tuple{tp})
	if err != nil {
		t.Fatalf("second grant failed: %v", err)
	}
	if applied2 {
		t.Fatalf("second grant applied = true, want false (idempotent by natural key): %s", detail2)
	}
	t.Logf("second: %s", detail2)
}

// TestSeed_SeedStepEmptyStructuralTuplesConverges proves SeedStep's authz half is a documented,
// harmless no-op (StructuralTuples is empty — see seed.go's comment).
func TestSeed_SeedStepEmptyStructuralTuplesConverges(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	deps := &Deps{AuthzPool: authzPool}

	outcome, detail, err := SeedStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("seed run failed: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged (registry skipped, no structural tuples configured): %s", outcome, detail)
	}
}

func TestSeedStep_Name(t *testing.T) {
	if got, want := (SeedStep{}).Name(), "seed"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

// TestSeedStep_Run_ParseInstalledModulesError proves KIBAN_INSTALLED_MODULES naming a module
// key that isn't in KnownModules fails the step loudly rather than
// silently ignoring the typo/drift.
func TestSeedStep_Run_ParseInstalledModulesError(t *testing.T) {
	registryPool := bootstrapServicePool(t, "kiban_registry", bootstrapTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
	deps := &Deps{RegistryPool: registryPool, InstalledModulesCSV: "totally-unknown-module-key"}

	outcome, _, err := SeedStep{}.Run(context.Background(), deps)
	if err == nil {
		t.Fatal("expected an error for an unknown module key in KIBAN_INSTALLED_MODULES")
	}
	if outcome != OutcomeFailed {
		t.Errorf("outcome = %s, want failed", outcome)
	}
}

// TestSeedStep_Run_RegistryQueryErrors forces the two DB-facing branches around
// registry.Store.Seed to fail via an already-canceled context: with KnownModules empty (this
// package's own production default), the "before" installation-row count short-circuits without
// querying (len(known)==0), so the canceled context first bites inside registry.Store.Seed
// itself — proving Run's Seed-error wrap. The "before" count's OWN error branch needs a
// non-empty KnownModules list to reach a real query at all; seed_test.go's own established
// pattern (TestSeed_RegistryCAP001...) swaps KnownModules for exactly this reason.
func TestSeedStep_Run_RegistryQueryErrors(t *testing.T) {
	registryPool := bootstrapServicePool(t, "kiban_registry", bootstrapTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))

	t.Run("registry.Store.Seed error (before-count succeeds trivially, Seed itself rejects an invalid module key)", func(t *testing.T) {
		origKnown := KnownModules
		// registry.Store.Seed validates ModuleKey against its own pattern BEFORE ever touching
		// the DB (internal/registry/seed.go's moduleKeyPattern) — an invalid key fails there
		// immediately, deterministically, no context-cancellation timing needed. The "before"
		// count query still runs normally (real, uncanceled context) and succeeds trivially.
		KnownModules = []registry.ModuleManifest{{ModuleKey: "Invalid-Key-Format!", DisplayName: "x"}}
		t.Cleanup(func() { KnownModules = origKnown })

		deps := &Deps{RegistryPool: registryPool}
		outcome, _, err := SeedStep{}.Run(context.Background(), deps)
		if err == nil {
			t.Fatal("expected an error for an invalid module key")
		}
		if outcome != OutcomeFailed {
			t.Errorf("outcome = %s, want failed", outcome)
		}
	})

	t.Run("before-count error (non-empty KnownModules, canceled context)", func(t *testing.T) {
		origKnown := KnownModules
		KnownModules = []registry.ModuleManifest{{
			ModuleKey: "wp-count-err", DisplayName: "x", ScopeType: "global",
			BasePath: "/x", HealthPath: "/health", Port: 9999, LicenseClass: "foundation", ManifestVersion: "1.0.0",
		}}
		t.Cleanup(func() { KnownModules = origKnown })

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		deps := &Deps{RegistryPool: registryPool}
		outcome, _, err := SeedStep{}.Run(ctx, deps)
		if err == nil {
			t.Fatal("expected an error from a canceled context")
		}
		if outcome != OutcomeFailed {
			t.Errorf("outcome = %s, want failed", outcome)
		}
	})
}

// TestSeedStep_Run_AuthzTuplesError proves SeedStep.Run's own error-wrap around
// SeedStructuralTuples (a canceled context fails its tuplesExist pre-check).
func TestSeedStep_Run_AuthzTuplesError(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))

	origTuples := StructuralTuples
	StructuralTuples = []store.Tuple{{ObjectType: "system", ObjectID: "wp-seed-err", Relation: "superadmin", SubjectType: "user", SubjectID: "u1"}}
	t.Cleanup(func() { StructuralTuples = origTuples })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := &Deps{AuthzPool: authzPool}
	outcome, _, err := SeedStep{}.Run(ctx, deps)
	if err == nil {
		t.Fatal("expected an error from a canceled context")
	}
	if outcome != OutcomeFailed {
		t.Errorf("outcome = %s, want failed", outcome)
	}
}

// TestSeedStructuralTuples_PreCheckError and TestTuplesExist_QueryError both exercise the same
// underlying branch (a canceled context failing tuplesExist's own query) from two different
// call sites: directly, and through SeedStructuralTuples' own wrapping error.
func TestSeedStructuralTuples_PreCheckError(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	tp := store.Tuple{ObjectType: "system", ObjectID: "wp-seed-precheck-err", Relation: "superadmin", SubjectType: "user", SubjectID: "u1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := SeedStructuralTuples(ctx, authzPool, "bootstrap", []store.Tuple{tp}); err == nil {
		t.Fatal("expected an error from a canceled context")
	}
}

func TestTuplesExist_QueryError(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	tp := store.Tuple{ObjectType: "system", ObjectID: "wp-tuples-exist-err", Relation: "superadmin", SubjectType: "user", SubjectID: "u1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tuplesExist(ctx, authzPool, []store.Tuple{tp}); err == nil {
		t.Fatal("expected an error from a canceled context")
	}
}
