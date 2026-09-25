// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/rosschiu/kiban/internal/errenv"
)

func TestCapability_NotInstalled(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	// no installation row at all

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != errenv.CodeModuleNotInstalled {
		t.Errorf("code = %q, want %q", code, errenv.CodeModuleNotInstalled)
	}
	if cap.Installed || cap.Enabled {
		t.Errorf("cap = %+v, want installed=false enabled=false", cap)
	}
}

func TestCapability_Disabled(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != errenv.CodeModuleDisabled {
		t.Errorf("code = %q, want %q", code, errenv.CodeModuleDisabled)
	}
	if !cap.Installed || cap.Enabled {
		t.Errorf("cap = %+v, want installed=true enabled=false", cap)
	}
}

func TestCapability_MissingDependency_Direct(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertCatalogFixture(t, admin, "beta", false)
	insertInstallationFixture(t, admin, "alpha", true, true)
	insertInstallationFixture(t, admin, "beta", false, false)
	insertDependencyFixture(t, admin, "alpha", "beta")

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != errenv.CodeModuleDependencyMissing {
		t.Errorf("code = %q, want %q", code, errenv.CodeModuleDependencyMissing)
	}
	if !reflect.DeepEqual(cap.MissingDependencies, []string{"beta"}) {
		t.Errorf("missingDependencies = %v, want [beta]", cap.MissingDependencies)
	}
}

func TestCapability_MissingDependency_Transitive(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	// alpha -> beta -> gamma; gamma is not installed. alpha and beta themselves are
	// installed+enabled, so the only reason alpha isn't ready is the transitive dependency.
	insertCatalogFixture(t, admin, "alpha", false)
	insertCatalogFixture(t, admin, "beta", false)
	insertCatalogFixture(t, admin, "gamma", false)
	insertInstallationFixture(t, admin, "alpha", true, true)
	insertInstallationFixture(t, admin, "beta", true, true)
	insertInstallationFixture(t, admin, "gamma", false, false)
	insertDependencyFixture(t, admin, "alpha", "beta")
	insertDependencyFixture(t, admin, "beta", "gamma")

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != errenv.CodeModuleDependencyMissing {
		t.Errorf("code = %q, want %q", code, errenv.CodeModuleDependencyMissing)
	}
	gotDeps := append([]string{}, cap.Dependencies...)
	sort.Strings(gotDeps)
	if !reflect.DeepEqual(gotDeps, []string{"beta", "gamma"}) {
		t.Errorf("dependencies = %v, want [beta gamma]", gotDeps)
	}
	if !reflect.DeepEqual(cap.MissingDependencies, []string{"gamma"}) {
		t.Errorf("missingDependencies = %v, want [gamma] (transitive dep, not just direct)", cap.MissingDependencies)
	}
}

func TestCapability_Cycle(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	// alpha -> beta -> alpha (a genuine cycle). Both installed+enabled: the recursive CTE must
	// terminate (path-based cycle guard) instead of hanging, and the capability must resolve
	// as OK since every dependency in the closure is installed+enabled.
	insertCatalogFixture(t, admin, "alpha", false)
	insertCatalogFixture(t, admin, "beta", false)
	insertInstallationFixture(t, admin, "alpha", true, true)
	insertInstallationFixture(t, admin, "beta", true, true)
	insertDependencyFixture(t, admin, "alpha", "beta")
	insertDependencyFixture(t, admin, "beta", "alpha")

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error (likely a hang/timeout from an unguarded cycle): %v", err)
	}
	if code != "" {
		t.Errorf("code = %q, want \"\" (ok — cycle resolved, no hang)", code)
	}
	if !cap.Installed || !cap.Enabled {
		t.Errorf("cap = %+v, want installed=true enabled=true", cap)
	}
}

func TestCapability_Ok(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertCatalogFixture(t, admin, "beta", false)
	insertInstallationFixture(t, admin, "alpha", true, true)
	insertInstallationFixture(t, admin, "beta", true, true)
	insertDependencyFixture(t, admin, "alpha", "beta")

	store := NewStore(registryPool(t))
	cap, code, err := store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != "" {
		t.Errorf("code = %q, want \"\" (ok)", code)
	}
	if len(cap.MissingDependencies) != 0 {
		t.Errorf("missingDependencies = %v, want empty", cap.MissingDependencies)
	}
	if !cap.Installed || !cap.Enabled {
		t.Errorf("cap = %+v, want installed=true enabled=true", cap)
	}
}

func TestCapability_UnknownModule(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	_, _, err := store.Capability(context.Background(), "nosuchmodule")
	if !errors.Is(err, ErrModuleNotFound) {
		t.Errorf("err = %v, want ErrModuleNotFound", err)
	}
}
