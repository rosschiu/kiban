// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

// Live proof for PreflightStep.Run itself (preflight_test.go's own unit tests already cover the
// HTTP retry/error helpers without a stack) — the parts of Run that genuinely need Postgres/
// Keycloak: the `SELECT version()` probe and the discovery-URL fetch. KeycloakManagementURL
// (port 9000) isn't published to the host by infra/compose.yaml (only bootstrap, running
// inside the compose network, can reach it) — this test only exercises the discovery-URL leg,
// on the host-published app port, same as every other bootstrap live test's own base URL.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPreflightStep_Run_Live(t *testing.T) {
	pool := bootstrapAdminPool(t)
	realm := bootstrapTestEnv(t, "KEYCLOAK_REALM")
	discoveryURL := "http://127.0.0.1:" + bootstrapTestEnv(t, "KEYCLOAK_HOST_PORT") + "/realms/" + realm + "/.well-known/openid-configuration"

	t.Run("postgres reachable, discovery URL configured and reachable", func(t *testing.T) {
		deps := &Deps{
			Pool:                      pool,
			HTTPClient:                &http.Client{Timeout: 15 * time.Second},
			KeycloakRealmDiscoveryURL: discoveryURL,
		}
		outcome, detail, err := PreflightStep{}.Run(context.Background(), deps)
		if err != nil {
			t.Fatalf("Run: %v (detail: %s)", err, detail)
		}
		if outcome != OutcomeConverged {
			t.Errorf("outcome = %s, want converged", outcome)
		}
		if !strings.Contains(detail, "keycloakIssuer=") || strings.Contains(detail, `keycloakIssuer=""`) {
			t.Errorf("detail = %q, want a non-empty keycloakIssuer", detail)
		}
	})

	t.Run("no Keycloak URLs configured skips both checks", func(t *testing.T) {
		deps := &Deps{Pool: pool, HTTPClient: &http.Client{Timeout: 15 * time.Second}}
		outcome, detail, err := PreflightStep{}.Run(context.Background(), deps)
		if err != nil {
			t.Fatalf("Run: %v (detail: %s)", err, detail)
		}
		if outcome != OutcomeConverged {
			t.Errorf("outcome = %s, want converged", outcome)
		}
		if !strings.Contains(detail, `keycloakIssuer=""`) {
			t.Errorf("detail = %q, want an empty keycloakIssuer (both Keycloak checks skipped)", detail)
		}
	})

	t.Run("unreachable discovery URL fails the step", func(t *testing.T) {
		deps := &Deps{
			Pool:                      pool,
			HTTPClient:                &http.Client{Timeout: 15 * time.Second},
			KeycloakRealmDiscoveryURL: "http://127.0.0.1:1/realms/nope/.well-known/openid-configuration",
		}
		outcome, _, err := PreflightStep{}.Run(context.Background(), deps)
		if err == nil {
			t.Fatal("expected an error for an unreachable discovery URL")
		}
		if outcome != OutcomeFailed {
			t.Errorf("outcome = %s, want failed", outcome)
		}
	})

	t.Run("unreachable postgres pool fails the step before any Keycloak check", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // an already-canceled context makes the version() query fail immediately
		deps := &Deps{Pool: pool, HTTPClient: &http.Client{Timeout: 15 * time.Second}, KeycloakRealmDiscoveryURL: discoveryURL}
		outcome, _, err := PreflightStep{}.Run(ctx, deps)
		if err == nil {
			t.Fatal("expected an error for a canceled context")
		}
		if outcome != OutcomeFailed {
			t.Errorf("outcome = %s, want failed", outcome)
		}
	})
}
