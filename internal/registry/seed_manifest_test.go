// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"strings"
	"testing"
)

// TestValidateKnownManifests is the install-time half of module-contract §8's structural rules:
// the registry refuses a known set that the validator would refuse.
func TestValidateKnownManifests(t *testing.T) {
	if err := validateKnownManifests(testManifests()); err != nil {
		t.Fatalf("clean set: %v", err)
	}
	if err := validateKnownManifests(BuiltinModules); err != nil {
		t.Fatalf("built-in set: %v", err)
	}
	cases := map[string]func(m *ModuleManifest){
		"basePath":       func(m *ModuleManifest) { m.BasePath = "/api/other" },
		"port":           func(m *ModuleManifest) { m.Port = 0 },
		"healthPath":     func(m *ModuleManifest) { m.HealthPath = "health" },
		"duplicate port": func(m *ModuleManifest) { m.Port = 8202 },
		"duplicate key":  func(m *ModuleManifest) { m.ModuleKey = "spine"; m.BasePath = "/api/spine" },
	}
	for name, mutate := range cases {
		known := testManifests()
		mutate(&known[0])
		if err := validateKnownManifests(known); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestSeed_RequiredOrgUnitTypeMissing_Refuses proves install-time enforcement of
// org.requiredOrgUnitTypes against the deployment taxonomy (org.org_unit_type).
func TestSeed_RequiredOrgUnitTypeMissing_Refuses(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	known := testManifests()
	known[0].RequiredOrgUnitTypes = []string{"company", "galaxy"}
	err := store.Seed(context.Background(), known, map[string]bool{"alpha": true})
	if err == nil || !strings.Contains(err.Error(), "galaxy") {
		t.Fatalf("expected Seed to refuse the unknown org unit type, got: %v", err)
	}
	known[0].RequiredOrgUnitTypes = []string{"company"}
	if err := store.Seed(context.Background(), known, map[string]bool{"alpha": true}); err != nil {
		t.Fatalf("a taxonomy the deployment defines must seed: %v", err)
	}
}
