// SPDX-License-Identifier: Apache-2.0

// Package livestack is a shared guard that live-dependent test helpers and the infra/e2e-*.sh /
// modules/*/curl-proof.sh scripts use to detect when the deployment they would otherwise mutate
// is the PUBLIC stack (`make public-up`) rather than an
// isolated one: `make check`/`make test` must never mutate a deployment a human is using (test
// runs against a public deployment can revert realm redirect URIs, restore required actions, and
// truncate org tables).
package livestack

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PublicModeMarkerPath returns the absolute path to the marker file `make public-up` writes and
// `make dev`/`make dev-clean` remove (infra/.public-mode) — see the Makefile.
func PublicModeMarkerPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Unreachable in practice (runtime.Caller(0) always resolves the calling frame), but
		// fall back to a relative path rather than panicking.
		return filepath.Join("infra", ".public-mode")
	}
	// this file lives at <repoRoot>/internal/livestack/guard.go
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "infra", ".public-mode")
}

// InPublicMode reports whether the live stack is currently running in PUBLIC mode, per the
// marker file above. infra/e2e-*.sh and modules/*/curl-proof.sh (which always target the live
// stack's own fixed ports — they have no "isolated stack" mode) refuse outright on this alone.
func InPublicMode() bool {
	return inPublicModeAt(PublicModeMarkerPath())
}

// inPublicModeAt is InPublicMode's path-parameterized core — split out so guard_test.go can
// exercise every branch against a throwaway t.TempDir() marker file instead of ever touching the
// REAL infra/.public-mode (a test mutating the live stack is exactly what this package prevents,
// so its own tests must never do it). The public zero-arg functions below are
// the only thing any real caller (test helpers, e2e/curl-proof scripts' compiled Go, if any) ever
// uses; the parameterized versions are test-only surface, unexported on purpose.
func inPublicModeAt(markerPath string) bool {
	_, err := os.Stat(markerPath)
	return err == nil
}

// liveEnvPath returns .env's absolute path at the repository root (the LIVE stack's own env
// file — distinct from .env.test, the isolated test stack).
func liveEnvPath() string {
	return filepath.Join(filepath.Dir(PublicModeMarkerPath()), "..", ".env")
}

// liveEnvValueAt reads a single key's value directly out of an .env-shaped file (the real
// caller, TargetsLiveStack below, always passes liveEnvPath() — never .env.test — so it can
// tell whether the CURRENT process env has been redirected away from the live stack's own
// baseline port). Path-parameterized (rather than reading liveEnvPath() itself) for the same
// testability reason as inPublicModeAt above — lets guard_test.go supply a throwaway env file
// instead of the real .env.
func liveEnvValueAt(envPath, key string) string {
	f, err := os.Open(envPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// TargetsLiveStack reports whether a live-dependent test helper connecting right now would hit
// the LIVE stack (.env's own POSTGRES_HOST_PORT) while that stack is in PUBLIC mode — the
// actual condition Go test helpers must refuse on. `make test-stack-up`'s .env.test is a
// full copy of .env with its host ports remapped; the `make check`/`make test`
// targets source .env.test into the process environment before `go test` runs, so
// POSTGRES_HOST_PORT there is never .env's own value — deliberately targeting the isolated
// stack is NOT refused, even while the live stack is public. A caller that hasn't redirected
// POSTGRES_HOST_PORT at all (`go test` with no env, falling back to reading .env
// directly) IS refused.
func TargetsLiveStack() bool {
	return targetsLiveStackAt(PublicModeMarkerPath(), liveEnvPath(), os.Getenv("POSTGRES_HOST_PORT"))
}

// targetsLiveStackAt is TargetsLiveStack's fully-parameterized core (marker path, live env file
// path, and the CURRENT process's POSTGRES_HOST_PORT all supplied explicitly) — the actual
// decision table guard_test.go exercises directly, again so the real marker/env files are never
// touched by a test.
func targetsLiveStackAt(markerPath, envPath, currentPort string) bool {
	if !inPublicModeAt(markerPath) {
		return false
	}
	livePort := liveEnvValueAt(envPath, "POSTGRES_HOST_PORT")
	if livePort == "" {
		// Can't determine the live baseline — fail safe (refuse) rather than silently proceed.
		return true
	}
	return currentPort == "" || currentPort == livePort
}

// RefusalMessage is what live-dependent test helpers and infra/e2e-*.sh / modules/*/curl-proof.sh
// scripts fail with when InPublicMode() / TargetsLiveStack() is true.
const RefusalMessage = "refusing to run against the live stack: it is in PUBLIC mode (infra/.public-mode present) — use `make test-stack-up` and target that isolated stack instead"
