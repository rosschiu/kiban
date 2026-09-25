// SPDX-License-Identifier: Apache-2.0

package livestack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This package is the interlock keeping infra/e2e-*.sh / modules/*/curl-proof.sh / every
// live-dependent Go test helper off the PUBLIC deployment a human may be actively using. Every
// case below drives the path-parameterized `*At` cores — NEVER the real infra/.public-mode or
// .env — via t.TempDir() fixtures, so running this suite can never itself touch the live
// stack.

// writeMarker creates (or not) a marker file at dir/.public-mode and returns its path — present
// controls whether the file actually gets written, mirroring `make public-up`/`make dev-clean`'s
// touch/rm of the real file.
func writeMarker(t *testing.T, dir string, present bool) string {
	t.Helper()
	path := filepath.Join(dir, ".public-mode")
	if present {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatalf("write marker: %v", err)
		}
	}
	return path
}

// writeEnvFile writes a minimal .env-shaped file (comments + blank lines + KEY=VALUE) at
// dir/.env. postgresPort == "" omits the POSTGRES_HOST_PORT line entirely (the "can't determine
// baseline" case).
func writeEnvFile(t *testing.T, dir, postgresPort string) string {
	t.Helper()
	path := filepath.Join(dir, ".env")
	var sb strings.Builder
	sb.WriteString("# a comment, mirroring .env's own shape\n")
	sb.WriteString("\n")
	sb.WriteString("OTHER_VAR=irrelevant\n")
	if postgresPort != "" {
		sb.WriteString("POSTGRES_HOST_PORT=" + postgresPort + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return path
}

// ---- PublicModeMarkerPath / InPublicMode -------------------------------------------------------

func TestPublicModeMarkerPath_ResolvesUnderInfra(t *testing.T) {
	path := PublicModeMarkerPath()
	if !strings.HasSuffix(path, filepath.Join("infra", ".public-mode")) {
		t.Fatalf("PublicModeMarkerPath() = %q, want a path ending in infra/.public-mode", path)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("PublicModeMarkerPath() = %q, want an absolute path", path)
	}
}

func TestInPublicModeAt_MarkerPresent_True(t *testing.T) {
	dir := t.TempDir()
	marker := writeMarker(t, dir, true)
	if !inPublicModeAt(marker) {
		t.Fatal("expected inPublicModeAt to report true when the marker file exists")
	}
}

func TestInPublicModeAt_MarkerAbsent_False(t *testing.T) {
	dir := t.TempDir()
	marker := writeMarker(t, dir, false) // never written
	if inPublicModeAt(marker) {
		t.Fatal("expected inPublicModeAt to report false when the marker file does not exist")
	}
}

// ---- liveEnvValueAt -------------------------------------------------------------------------

func TestLiveEnvValueAt_KeyPresent(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, dir, "55432")
	if got := liveEnvValueAt(envPath, "POSTGRES_HOST_PORT"); got != "55432" {
		t.Fatalf("liveEnvValueAt = %q, want 55432", got)
	}
}

func TestLiveEnvValueAt_KeyAbsent_EmptyString(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, dir, "") // POSTGRES_HOST_PORT line omitted
	if got := liveEnvValueAt(envPath, "POSTGRES_HOST_PORT"); got != "" {
		t.Fatalf("liveEnvValueAt = %q, want empty string for a missing key", got)
	}
}

func TestLiveEnvValueAt_FileMissing_EmptyString(t *testing.T) {
	dir := t.TempDir()
	if got := liveEnvValueAt(filepath.Join(dir, "does-not-exist.env"), "POSTGRES_HOST_PORT"); got != "" {
		t.Fatalf("liveEnvValueAt = %q, want empty string when the env file itself doesn't exist", got)
	}
}

// ---- targetsLiveStackAt: the actual decision table --------------------------------------------

func TestTargetsLiveStackAt_Table(t *testing.T) {
	for _, tc := range []struct {
		name         string
		markerExists bool
		livePort     string // "" = POSTGRES_HOST_PORT absent from the live env file entirely
		currentPort  string
		want         bool
		reason       string
	}{
		{
			name:         "not public mode -> never refuse, regardless of ports",
			markerExists: false, livePort: "5432", currentPort: "5432",
			want: false, reason: "InPublicMode() alone gates everything below it",
		},
		{
			name:         "public mode, current port unset -> refuse (unredirected caller)",
			markerExists: true, livePort: "5432", currentPort: "",
			want: true, reason: "a caller that never redirected POSTGRES_HOST_PORT is exactly the shape that would mutate a live deployment",
		},
		{
			name:         "public mode, current port matches live -> refuse",
			markerExists: true, livePort: "5432", currentPort: "5432",
			want: true, reason: "current env still points at the live stack's own port",
		},
		{
			name:         "public mode, current port redirected to isolated stack -> allow",
			markerExists: true, livePort: "5432", currentPort: "55432",
			want: false, reason: "make test-stack-up's .env.test remaps the port; a deliberately-isolated target is not refused even while public",
		},
		{
			name:         "public mode, live baseline undeterminable (no .env at all) -> fail-safe refuse",
			markerExists: true, livePort: "", currentPort: "55432",
			want: true, reason: "can't prove the current port DIFFERS from an unknown live baseline, so refuse rather than silently proceed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := writeMarker(t, dir, tc.markerExists)
			envPath := writeEnvFile(t, dir, tc.livePort)

			got := targetsLiveStackAt(marker, envPath, tc.currentPort)
			if got != tc.want {
				t.Fatalf("targetsLiveStackAt(marker exists=%v, livePort=%q, currentPort=%q) = %v, want %v (%s)",
					tc.markerExists, tc.livePort, tc.currentPort, got, tc.want, tc.reason)
			}
		})
	}
}

// TestTargetsLiveStackAt_LiveEnvFileEntirelyMissing covers the case where .env itself
// doesn't exist at the given path (distinct from existing-but-missing-the-key above) — same
// fail-safe-refuse outcome via liveEnvValueAt's file-open error path.
func TestTargetsLiveStackAt_LiveEnvFileEntirelyMissing(t *testing.T) {
	dir := t.TempDir()
	marker := writeMarker(t, dir, true)
	missingEnvPath := filepath.Join(dir, "does-not-exist.env")

	if !targetsLiveStackAt(marker, missingEnvPath, "55432") {
		t.Fatal("expected fail-safe refuse when the live env file can't be opened at all")
	}
}

// ---- the real, zero-arg entry points (sanity-check they compose the *At cores correctly, ------
// ---- WITHOUT touching the real infra/.public-mode / .env) --------------------------------

// TestInPublicMode_ComposesRealMarkerPath proves InPublicMode() is wired to
// PublicModeMarkerPath() (not a copy/paste-diverged path) by checking it agrees with a direct
// os.Stat of that same path — read-only, never creates or deletes the real marker.
func TestInPublicMode_ComposesRealMarkerPath(t *testing.T) {
	_, statErr := os.Stat(PublicModeMarkerPath())
	want := statErr == nil
	if got := InPublicMode(); got != want {
		t.Fatalf("InPublicMode() = %v, want %v (agreeing with a direct os.Stat of PublicModeMarkerPath())", got, want)
	}
}

// TestTargetsLiveStack_ComposesRealPaths proves TargetsLiveStack() is wired to
// PublicModeMarkerPath()/liveEnvPath()/os.Getenv("POSTGRES_HOST_PORT") (not a copy/paste-diverged
// set of paths) by checking it agrees with targetsLiveStackAt called directly on those same real
// values — read-only throughout, never creates/deletes/writes infra/.public-mode or .env.
func TestTargetsLiveStack_ComposesRealPaths(t *testing.T) {
	want := targetsLiveStackAt(PublicModeMarkerPath(), liveEnvPath(), os.Getenv("POSTGRES_HOST_PORT"))
	if got := TargetsLiveStack(); got != want {
		t.Fatalf("TargetsLiveStack() = %v, want %v (agreeing with targetsLiveStackAt on the real marker/env paths)", got, want)
	}
}

// ---- RefusalMessage -----------------------------------------------------------------------------

func TestRefusalMessage_NamesPublicModeAndTheEscapeHatch(t *testing.T) {
	for _, want := range []string{"PUBLIC mode", "make test-stack-up", "infra/.public-mode"} {
		if !strings.Contains(RefusalMessage, want) {
			t.Fatalf("RefusalMessage = %q, want it to mention %q", RefusalMessage, want)
		}
	}
}
