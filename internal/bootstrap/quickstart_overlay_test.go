// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The published-image quickstart must be able to serve a real origin (TokiDesk spike, K9):
// deploy/quickstart/compose.public.yaml, generated from infra/compose.public.yaml, carries the
// origin-dependent settings for every service the quickstart runs, and nothing tied to the
// source tree's shared-Traefik topology.
func TestQuickstartPublicOverlayServesAPublicOrigin(t *testing.T) {
	type service struct {
		Environment map[string]string `yaml:"environment"`
		Labels      map[string]string `yaml:"labels"`
		Networks    []string          `yaml:"networks"`
	}
	load := func(path string) map[string]service {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Services map[string]service `yaml:"services"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return doc.Services
	}
	base := load("../../deploy/quickstart/docker-compose.yml")
	overlay := load("../../deploy/quickstart/compose.public.yaml")

	const issuer = "https://${KIBAN_PUBLIC_HOST:?KIBAN_PUBLIC_HOST is required}/realms/${KEYCLOAK_REALM:-kiban}"
	const domain = "${KIBAN_PUBLIC_HOST:?KIBAN_PUBLIC_HOST is required}"

	for name, s := range overlay {
		if _, ok := base[name]; !ok {
			t.Errorf("overlay names service %q that the quickstart does not run", name)
		}
		if len(s.Labels) != 0 || len(s.Networks) != 0 {
			t.Errorf("service %q carries labels/networks from the shared-Traefik topology", name)
		}
	}
	// Every service that verifies tokens itself must expect the public issuer.
	for name, s := range base {
		if _, verifies := s.Environment["KEYCLOAK_ISSUER_URL"]; !verifies {
			continue
		}
		if got := overlay[name].Environment["KEYCLOAK_ISSUER_URL"]; got != issuer {
			t.Errorf("%s: KEYCLOAK_ISSUER_URL = %q, want %q", name, got, issuer)
		}
	}
	if got := overlay["gateway"].Environment["KIBAN_DOMAIN"]; got != domain {
		t.Errorf("gateway KIBAN_DOMAIN = %q, want %q", got, domain)
	}
	if got := overlay["bootstrap"].Environment["KIBAN_DOMAIN"]; got != domain {
		t.Errorf("bootstrap KIBAN_DOMAIN = %q, want %q", got, domain)
	}
	if got := overlay["gateway"].Environment["KIBAN_TRUSTED_PROXY"]; got != "true" {
		t.Errorf("gateway KIBAN_TRUSTED_PROXY = %q, want true", got)
	}
	if got := overlay["keycloak"].Environment["KC_HOSTNAME"]; !strings.HasPrefix(got, "https://${KIBAN_PUBLIC_HOST") {
		t.Errorf("keycloak KC_HOSTNAME = %q, want it pinned to the public origin", got)
	}
	if got := overlay["keycloak"].Environment["KC_HOSTNAME_STRICT"]; got != "true" {
		t.Errorf("keycloak KC_HOSTNAME_STRICT = %q, want true", got)
	}
}
