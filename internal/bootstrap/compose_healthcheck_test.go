// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The Keycloak healthcheck in infra/compose.yaml (and the generated quickstart copy) must
// look at the HTTP status line, not at a `"status": "UP"` fragment: Keycloak's readiness body
// while it initialises is a 503 whose per-check list contains an UP entry ("Graceful
// Shutdown"), which used to flip the container healthy and start bootstrap too early.
func TestComposeKeycloakHealthcheckMatchesStatusLine(t *testing.T) {
	for _, file := range []string{"../../infra/compose.yaml", "../../deploy/quickstart/docker-compose.yml"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`grep -q '([^']+)' <&3`).FindStringSubmatch(string(raw))
		if m == nil {
			t.Fatalf("%s: keycloak healthcheck grep not found", file)
		}
		pattern := strings.ReplaceAll(m[1], `\"`, `"`)

		starting := "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\n\r\n" +
			"{\n    \"status\": \"DOWN\",\n    \"checks\": [\n        {\n            \"name\": \"Graceful Shutdown\",\n            \"status\": \"UP\"\n        },\n" +
			"        {\n            \"name\": \"Keycloak Initialized\",\n            \"status\": \"DOWN\"\n        }\n    ]\n}"
		ready := "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\n    \"status\": \"UP\",\n    \"checks\": []\n}"

		grep := func(body string) bool {
			cmd := exec.Command("grep", "-q", pattern)
			cmd.Stdin = strings.NewReader(body)
			return cmd.Run() == nil
		}
		if grep(starting) {
			t.Errorf("%s: pattern %q matches a still-initialising 503 body", file, pattern)
		}
		if !grep(ready) {
			t.Errorf("%s: pattern %q does not match the ready 200 response", file, pattern)
		}
	}
}

// Bootstrap's own readiness retry must outlast a cold Keycloak start (observed: over 30s on a
// loaded host after the container was already "healthy").
func TestKeycloakReadyRetryBudgetCoversColdStart(t *testing.T) {
	if budget := time.Duration(keycloakReadyRetries) * keycloakReadyRetryDelay; budget < 60*time.Second {
		t.Fatalf("retry budget %v is shorter than a cold Keycloak start", budget)
	}
}
