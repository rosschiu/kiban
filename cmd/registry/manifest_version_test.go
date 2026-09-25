// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	docsartifacts "github.com/rosschiu/kiban/modules/docs"
	helpdeskartifacts "github.com/rosschiu/kiban/modules/helpdesk"
	notificationartifacts "github.com/rosschiu/kiban/modules/notification"
	timesheetartifacts "github.com/rosschiu/kiban/modules/timesheet"
)

// TestBuiltinModules_VersionMatchesManifest guards against catalog/installation rows Seed()
// writes disagreeing with the shipped artifacts. This proves, for every known
// module, that builtinModules' ManifestVersion is sourced from (and therefore always equals) the
// module's own embedded module.manifest.json "version" field — no live stack needed, this is a
// pure in-process comparison against the same embeds artifacts.go carries.
func TestBuiltinModules_VersionMatchesManifest(t *testing.T) {
	manifestJSONByKey := map[string][]byte{
		"notification": notificationartifacts.ManifestJSON,
		"timesheet":    timesheetartifacts.ManifestJSON,
		"docs":         docsartifacts.ManifestJSON,
		"helpdesk":     helpdeskartifacts.ManifestJSON,
	}

	if len(builtinModules) != len(manifestJSONByKey) {
		t.Fatalf("builtinModules has %d entries, want %d (one per known module: keep this test's map in sync when a module is added)", len(builtinModules), len(manifestJSONByKey))
	}

	for _, mod := range builtinModules {
		manifestJSON, ok := manifestJSONByKey[mod.ModuleKey]
		if !ok {
			t.Errorf("builtinModules has unknown module key %q with no manifest embed to compare against", mod.ModuleKey)
			continue
		}
		var manifest struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
			t.Fatalf("%s: parse module.manifest.json: %v", mod.ModuleKey, err)
		}
		if manifest.Version == "" {
			t.Fatalf("%s: module.manifest.json has no \"version\" field", mod.ModuleKey)
		}
		if mod.ManifestVersion != manifest.Version {
			t.Errorf("%s: builtinModules.ManifestVersion = %q, module.manifest.json version = %q — catalog/installation rows would disagree with the shipped artifact", mod.ModuleKey, mod.ManifestVersion, manifest.Version)
		}
	}
}
