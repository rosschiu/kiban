// SPDX-License-Identifier: Apache-2.0

//go:build harness

package harness

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// dockerAvailable reports whether a usable Docker daemon is reachable — the harness's "skip
// loudly, don't fail" gate (Design: "skipped with a loud warning if Docker absent").
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

const containerName = "kiban-openfga-harness"

// StartOpenFGA runs the openfga/openfga container on fixed local ports (127.0.0.1-bound,
// matching the rest of this repo's "everything localhost until the gateway" convention),
// waits for its healthz, and returns a stop func. Any prior leftover container with the same
// name is force-removed first (idempotent re-runs).
func StartOpenFGA(ctx context.Context, httpPort, grpcPort int) (baseURL string, stop func(), err error) {
	_ = exec.Command("docker", "rm", "-f", containerName).Run() //nolint:errcheck // best-effort cleanup of a prior run

	runArgs := []string{
		"run", "-d", "--name", containerName,
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", httpPort),
		"-p", fmt.Sprintf("127.0.0.1:%d:8081", grpcPort),
		"openfga/openfga:v1.12.0", "run",
	}
	if out, runErr := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput(); runErr != nil {
		return "", nil, fmt.Errorf("docker run openfga: %w (%s)", runErr, string(out))
	}

	stop = func() { _ = exec.Command("docker", "rm", "-f", containerName).Run() } //nolint:errcheck

	baseURL = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	client := NewClient(baseURL)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		healthy := client.Healthy(healthCtx)
		cancel()
		if healthy {
			return baseURL, stop, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	stop()
	return "", nil, fmt.Errorf("openfga container did not become healthy within 30s")
}
