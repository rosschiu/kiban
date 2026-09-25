// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// keycloakReadyRetries/keycloakReadyRetryDelay and realmDiscoveryRetries/realmDiscoveryRetryDelay
// port infra/bootstrap-stub/entrypoint.sh's own retry counts: compose's healthcheck on
// Keycloak's management port (9000) only needs ONE
// success to flip the container to "healthy" and release depends_on, but the APP port (8080,
// what these two checks actually hit) can still answer 503 for a few seconds after that first
// success while realm import finishes. A single unretried check here would make PreflightStep
// fail the whole bootstrap run on exactly the startup race the stub always retried through.
const (
	keycloakReadyRetries     = 15
	keycloakReadyRetryDelay  = 2 * time.Second
	realmDiscoveryRetries    = 10
	realmDiscoveryRetryDelay = 2 * time.Second
)

// PreflightStep proves the two hard dependencies every later step needs before touching
// anything: Postgres reachable (as the owner role) and — when configured — Keycloak ready with
// its realm actually imported (ports infra/bootstrap-stub/entrypoint.sh's shell checks into
// Go, versions logged instead of just a pass/fail exit code). Preflight is
// read-only, so a successful run is always "converged" — there is nothing for it to "apply".
type PreflightStep struct{}

func (PreflightStep) Name() string { return "preflight" }

func (PreflightStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	var pgVersion string
	if err := deps.Pool.QueryRow(ctx, `SELECT version()`).Scan(&pgVersion); err != nil {
		return OutcomeFailed, "", fmt.Errorf("preflight: postgres unreachable: %w", err)
	}

	issuer := ""
	if deps.KeycloakManagementURL != "" {
		if err := checkKeycloakReady(ctx, deps.HTTPClient, deps.KeycloakManagementURL); err != nil {
			return OutcomeFailed, "", fmt.Errorf("preflight: keycloak not ready: %w", err)
		}
	}
	if deps.KeycloakRealmDiscoveryURL != "" {
		var err error
		issuer, err = fetchRealmIssuer(ctx, deps.HTTPClient, deps.KeycloakRealmDiscoveryURL)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("preflight: realm not imported: %w", err)
		}
	}

	return OutcomeConverged, fmt.Sprintf("postgres=%q keycloakIssuer=%q", pgVersion, issuer), nil
}

func checkKeycloakReady(ctx context.Context, client *http.Client, baseURL string) error {
	var lastErr error
	for attempt := 0; attempt < keycloakReadyRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(keycloakReadyRetryDelay):
			}
		}
		lastErr = tryKeycloakReady(ctx, client, baseURL)
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func tryKeycloakReady(ctx context.Context, client *http.Client, baseURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health/ready", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keycloak health: HTTP %d", resp.StatusCode)
	}
	return nil
}

func fetchRealmIssuer(ctx context.Context, client *http.Client, discoveryURL string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < realmDiscoveryRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(realmDiscoveryRetryDelay):
			}
		}
		issuer, err := tryFetchRealmIssuer(ctx, client, discoveryURL)
		if err == nil {
			return issuer, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func tryFetchRealmIssuer(ctx context.Context, client *http.Client, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("realm discovery: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Issuer == "" {
		return "", fmt.Errorf("realm discovery: empty issuer")
	}
	return body.Issuer, nil
}
