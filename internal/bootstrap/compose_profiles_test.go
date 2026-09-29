// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every sample module carries the shared `samples` profile and its own, so one sample can be
// started alone; nothing in the foundation carries a profile.
func TestComposeSampleModulesHaveOwnProfiles(t *testing.T) {
	raw, err := os.ReadFile("../../infra/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Profiles []string `yaml:"profiles"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"notification", "timesheet", "docs", "helpdesk"} {
		p := doc.Services[m].Profiles
		if !slices.Contains(p, "samples") || !slices.Contains(p, m) {
			t.Errorf("%s profiles = %v, want both samples and %s", m, p, m)
		}
	}
	for _, f := range []string{"gateway", "registry", "identity", "org", "authz", "keycloak", "postgres", "bootstrap", "migrate"} {
		if p := doc.Services[f].Profiles; len(p) != 0 {
			t.Errorf("%s carries profiles %v; the foundation must always start", f, p)
		}
	}
}
