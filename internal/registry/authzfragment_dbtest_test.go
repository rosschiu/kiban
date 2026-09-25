// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"strings"
	"testing"
)

const validFragment = `{"widget":{"owner":{"this":true}}}`
const invalidFragment = `{"widget":{"owner":{"intersection":[{"this":true}]}}}`

// TestSeed_InstallsAuthzFragment_ActiveMirrorsEnabled proves Seed
// upserts a fragment-carrying module's authz.fragment.json relations into authz.model_fragment,
// with active mirroring the module's real (installed && enabled) state — not a naive copy of the
// installedKeys argument.
func TestSeed_InstallsAuthzFragment_ActiveMirrorsEnabled(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(validFragment)},
	}
	if err := store.Seed(context.Background(), manifests, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	fragment, active, found := getModelFragment(t, admin, "widget")
	if !found {
		t.Fatal("expected a model_fragment row for \"widget\"")
	}
	if !active {
		t.Error("expected active=true for an installed+enabled module")
	}
	if string(fragment) == "" {
		t.Error("expected a non-empty stored fragment")
	}
}

// TestSeed_InstallsAuthzFragment_ActiveFalseWhenNotInstalled proves the active flag reflects the
// module's real installed/enabled state, not installedKeys blindly.
func TestSeed_InstallsAuthzFragment_ActiveFalseWhenNotInstalled(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(validFragment)},
	}
	if err := store.Seed(context.Background(), manifests, map[string]bool{}); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	_, active, found := getModelFragment(t, admin, "widget")
	if !found {
		t.Fatal("expected a model_fragment row for \"widget\" even when not installed")
	}
	if active {
		t.Error("expected active=false for a module that isn't installed")
	}
}

// TestSeed_InvalidFragment_RefusesLoudly proves the subset-wall validation:
// a fragment using a construct outside the supported subset (here, "intersection") makes Seed fail
// instead of silently writing a bad row.
func TestSeed_InvalidFragment_RefusesLoudly(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(invalidFragment)},
	}
	err := store.Seed(context.Background(), manifests, map[string]bool{"widget": true})
	if err == nil {
		t.Fatal("expected Seed to refuse an invalid (outside-the-subset-wall) fragment")
	}

	if _, _, found := getModelFragment(t, admin, "widget"); found {
		t.Error("an invalid fragment must never be written")
	}
}

// TestSeed_NoFragment_NoModelFragmentRow proves a module without an authz fragment is a no-op on
// authz.model_fragment (not every module declares one).
func TestSeed_NoFragment_NoModelFragmentRow(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "plain", DisplayName: "Plain", ScopeType: "company", BasePath: "/api/plain",
			HealthPath: "/health", Port: 8301, LicenseClass: "foundation", ManifestVersion: "0.1.0"},
	}
	if err := store.Seed(context.Background(), manifests, map[string]bool{"plain": true}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if _, _, found := getModelFragment(t, admin, "plain"); found {
		t.Error("a module with no AuthzFragment must not get a model_fragment row")
	}
}

// TestSetEnabled_TogglesFragmentActive_Inert proves SetEnabled keeps model_fragment.active in
// lockstep: disable flips it false (inert), re-enable flips it back true, and the row
// itself is never deleted (fragment.go's own audit posture).
func TestSetEnabled_TogglesFragmentActive_Inert(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifests := []ModuleManifest{
		{ModuleKey: "widget", DisplayName: "Widget", ScopeType: "company", BasePath: "/api/widget",
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(validFragment)},
	}
	if err := store.Seed(context.Background(), manifests, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if _, active, _ := getModelFragment(t, admin, "widget"); !active {
		t.Fatal("precondition: expected active=true right after seeding enabled")
	}

	if _, err := store.SetEnabled(context.Background(), "widget", false, nil); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	fragment, active, found := getModelFragment(t, admin, "widget")
	if !found {
		t.Fatal("disabling must never delete the model_fragment row")
	}
	if active {
		t.Error("expected active=false after disable")
	}
	if len(fragment) == 0 {
		t.Error("the fragment bytes must survive a disable")
	}

	if _, err := store.SetEnabled(context.Background(), "widget", true, nil); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if _, active, _ := getModelFragment(t, admin, "widget"); !active {
		t.Error("expected active=true after re-enable")
	}
}

// TestSetEnabled_NoFragmentRow_NoOp proves toggling a module with no fragment row is a silent
// no-op (nothing to flip), not an error.
func TestSetEnabled_NoFragmentRow_NoOp(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "plain", false)
	insertInstallationFixture(t, admin, "plain", true, true)

	store := NewStore(registryPool(t))
	if _, err := store.SetEnabled(context.Background(), "plain", false, nil); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, _, found := getModelFragment(t, admin, "plain"); found {
		t.Error("expected no model_fragment row to appear for a module that never had one")
	}
}

// TestSeed_FragmentTypeDeclaredByTwoModules_RefusesSecond proves the install-time half of "one
// module owns an object type": the second module whose fragment
// declares a type an already-stored fragment declares is refused, naming the first module, and
// nothing is written for it.
func TestSeed_FragmentTypeDeclaredByTwoModules_RefusesSecond(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	manifest := func(key string) ModuleManifest {
		return ModuleManifest{ModuleKey: key, DisplayName: key, ScopeType: "company", BasePath: "/api/" + key,
			HealthPath: "/health", Port: 8300, LicenseClass: "foundation", ManifestVersion: "0.1.0",
			AuthzFragment: []byte(validFragment)}
	}
	if err := store.Seed(context.Background(), []ModuleManifest{manifest("widget")}, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("Seed(widget): %v", err)
	}
	err := store.Seed(context.Background(), []ModuleManifest{manifest("gadget")}, map[string]bool{"gadget": true})
	if err == nil {
		t.Fatal("expected Seed to refuse a second module declaring widget's object type")
	}
	if !strings.Contains(err.Error(), `"widget"`) || !strings.Contains(err.Error(), `"gadget"`) {
		t.Fatalf("error %q must name both modules", err.Error())
	}
	if _, _, found := getModelFragment(t, admin, "gadget"); found {
		t.Error("the refused fragment must never be written")
	}
	// Re-seeding the owner itself is an upsert, not a collision with its own row.
	if err := store.Seed(context.Background(), []ModuleManifest{manifest("widget")}, map[string]bool{"widget": true}); err != nil {
		t.Fatalf("re-Seed(widget): %v", err)
	}
}
