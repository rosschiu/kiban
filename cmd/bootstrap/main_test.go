// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/livestack"
)

// run() is exercised against the real dev stack: Postgres is never mocked here.
//
// Every step this file exercises is safe to re-run against an already-converged stack:
// idempotent create-if-missing/update-if-different bodies short-circuit on a converged stack —
// this file's own full-run test is simply that same proof, one level up, at cmd/bootstrap's own
// wiring. See setBootstrapEnv for why RealmStep never touches a real service secret here.

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// repoRootAbs returns this file's own repo root as an absolute path — run()'s
// KIBAN_REPO_ROOT/KIBAN_MIGRATIONS_ROOT default to the container path (/src), which does not
// exist on a host-run test process; MigrationsStep shells out to `go tool tern` with cmd.Dir set
// to this value, so it must be the real, host-visible repo root.
func repoRootAbs(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine caller for repo root lookup")
	}
	abs, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return abs
}

// readSuperadminPassword reads infra/secrets-in/superadmin-password — the same file `make dev`
// generates and the real bootstrap container reads via KIBAN_SUPERADMIN_PASSWORD_FILE.
func readSuperadminPassword(t *testing.T, repoRoot string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "infra", "secrets-in", "superadmin-password"))
	if err != nil {
		t.Fatalf("read superadmin password: %v (is the dev stack configured? see .env.example)", err)
	}
	return strings.TrimSpace(string(b))
}

// setBootstrapEnv sets every env var run()'s config.Spec reads to real dev-stack values
// (host-run, not compose — 127.0.0.1:<POSTGRES_HOST_PORT>, the owner role, real per-service
// role passwords). KEYCLOAK_REALM_DISCOVERY_URL points at the real host-published Keycloak app
// port, so
// PreflightStep's realm-imported check runs for real; KEYCLOAK_MANAGEMENT_URL stays empty since
// Keycloak's management port (9000) is compose-internal only, never published to the host.
func setBootstrapEnv(t *testing.T) {
	t.Helper()
	repoRoot := repoRootAbs(t)
	realm := testEnv(t, "KEYCLOAK_REALM")
	kcHostPort := testEnv(t, "KEYCLOAK_HOST_PORT")
	env := map[string]string{
		"KIBAN_DB_HOST":     "127.0.0.1",
		"KIBAN_DB_PORT":     testEnv(t, "POSTGRES_HOST_PORT"),
		"POSTGRES_DB":       testEnv(t, "POSTGRES_DB"),
		"KIBAN_DB_PASSWORD": testEnv(t, "KIBAN_DB_PASSWORD"),

		"KIBAN_REGISTRY_DB_PASSWORD": testEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"),
		"KIBAN_IDENTITY_DB_PASSWORD": testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD"),
		"KIBAN_ORG_DB_PASSWORD":      testEnv(t, "KIBAN_ORG_DB_PASSWORD"),
		"KIBAN_AUTHZ_DB_PASSWORD":    testEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"),

		"KEYCLOAK_MANAGEMENT_URL":      "",
		"KEYCLOAK_REALM_DISCOVERY_URL": "http://127.0.0.1:" + kcHostPort + "/realms/" + realm + "/.well-known/openid-configuration",

		"KIBAN_REPO_ROOT":                 repoRoot,
		"KIBAN_MIGRATIONS_ROOT":           filepath.Join(repoRoot, "migrations"),
		"KIBAN_SET_ROLE_PASSWORDS_SCRIPT": filepath.Join(repoRoot, "migrations", "registry", "set-role-passwords.sh"),

		// RealmStep/SuperadminStep both run for real here — safe because RealmStep's own
		// writeServiceSecrets is a no-op whenever KIBAN_SECRETS_DIR is
		// empty (checked FIRST, before any Keycloak client-secret call — see
		// internal/bootstrap/realm.go's writeServiceSecrets), so nothing here ever reads,
		// rotates, or writes any service's actual auth secret; every other RealmStep sub-step
		// is converge-if-different against state a prior real `make dev` bootstrap run already
		// created, so a second run reports "converged", not "applied".
		"KEYCLOAK_ADMIN_BASE_URL":         "http://127.0.0.1:" + kcHostPort,
		"KEYCLOAK_REALM":                  realm,
		"KC_BOOTSTRAP_ADMIN_USERNAME":     testEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME"),
		"KC_BOOTSTRAP_ADMIN_PASSWORD":     testEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD"),
		"KIBAN_DOMAIN":                    "",
		"KEYCLOAK_IDENTITY_CLIENT_SECRET": "",
		"KIBAN_SECRETS_DIR":               "", // keeps writeServiceSecrets a no-op — see above

		"KIBAN_SUPERADMIN_USERNAME": testEnv(t, "KIBAN_SUPERADMIN_USERNAME"),
		"KIBAN_SUPERADMIN_EMAIL":    testEnv(t, "KIBAN_SUPERADMIN_EMAIL"),
		"KIBAN_INSTALLED_MODULES":   "",
		// Real superadmin password (infra/secrets-in/superadmin-password, the same file `make
		// dev` generates and the real bootstrap container reads) — needed in case SuperadminStep
		// finds no `system:platform#superadmin` tuple and must (re-)create one; its own
		// Keycloak-side lookup-before-create means a prior run's Keycloak user is reused, never
		// duplicated.
		"KIBAN_SUPERADMIN_PASSWORD": readSuperadminPassword(t, repoRoot),

		"KIBAN_REGISTRY_DB_HOST": "127.0.0.1",
		"KIBAN_REGISTRY_DB_PORT": testEnv(t, "POSTGRES_HOST_PORT"),
		"KIBAN_REGISTRY_DB_NAME": testEnv(t, "POSTGRES_DB"),
		"KIBAN_AUTHZ_DB_HOST":    "127.0.0.1",
		"KIBAN_AUTHZ_DB_PORT":    testEnv(t, "POSTGRES_HOST_PORT"),
		"KIBAN_AUTHZ_DB_NAME":    testEnv(t, "POSTGRES_DB"),
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestRun_MissingConfigErrors proves run() surfaces config.Load's MissingError as a wrapped
// "load config" failure, before any network/DB call is attempted — the fast, infra-free path.
func TestRun_MissingConfigErrors(t *testing.T) {
	for _, k := range []string{
		"KIBAN_DB_HOST", "KIBAN_DB_PORT", "POSTGRES_DB", "KIBAN_DB_PASSWORD",
		"KIBAN_REGISTRY_DB_PASSWORD", "KIBAN_IDENTITY_DB_PASSWORD", "KIBAN_ORG_DB_PASSWORD",
		"KIBAN_AUTHZ_DB_PASSWORD",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("KIBAN_DB_PORT", "5432")
	t.Setenv("POSTGRES_DB", "kiban")
	// KIBAN_DB_PASSWORD and the four per-service *_DB_PASSWORD fields intentionally left unset.

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("err = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_DBUnreachableErrors proves run() fails fast (wrapped "ping database") when the
// configured Postgres host is unreachable — no migrations, no Keycloak call, is ever attempted.
func TestRun_DBUnreachableErrors(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_DB_HOST", "127.0.0.1")
	t.Setenv("KIBAN_DB_PORT", "1") // reserved/unlisted port — connection refused

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for an unreachable database, got nil")
	}
	if !strings.Contains(err.Error(), "database") {
		t.Errorf("err = %v, want it to mention the database step", err)
	}
}

// TestRun_DBDSNMalformedErrors proves the OTHER database-step failure branch: pgxpool.New itself
// rejecting a malformed DSN (never even attempting a connection).
func TestRun_DBDSNMalformedErrors(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_DB_PORT", "not-a-port") // fails DSN URL parsing inside pgxpool.New

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for a malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to database") {
		t.Errorf("err = %v, want it to wrap \"connect to database\"", err)
	}
}

// TestRun_OptionalServicePool_ConnectErrorWrapped proves optionalServicePool's own "connect to
// <service> database as <role>" failure branch: a malformed per-service DSN (registry's own
// port set to an unparseable value, while host/name stay set — the "test-only escape hatch"
// only skips the pool when host/name are BOTH empty) surfaces wrapped and stops run() before any
// step executes.
func TestRun_OptionalServicePool_ConnectErrorWrapped(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_REGISTRY_DB_PORT", "not-a-port")

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for a malformed registry-service DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to registry database") {
		t.Errorf("err = %v, want it to wrap \"connect to registry database\"", err)
	}
}

// TestRun_OptionalServicePool_PingErrorWrapped proves optionalServicePool's "ping <service>
// database as <role>" failure branch: a reachable host/port but wrong per-service role password
// authenticates-fails at Ping (not at pgxpool.New, which is lazy).
func TestRun_OptionalServicePool_PingErrorWrapped(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_REGISTRY_DB_PASSWORD", "definitely-the-wrong-password")

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for a wrong registry-service DB password, got nil")
	}
	if !strings.Contains(err.Error(), "ping registry database") {
		t.Errorf("err = %v, want it to wrap \"ping registry database\"", err)
	}
}

// TestRun_OptionalServicePool_SkippedWhenPortAndNameEmpty proves the documented skip branch:
// leaving a service's DB port+name both empty is a no-op, not an error — Superadmin/Seed/Verify
// all handle a nil pool for that service gracefully (see internal/bootstrap's own Deps-nil
// branches), so the whole run still converges successfully.
func TestRun_OptionalServicePool_SkippedWhenPortAndNameEmpty(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_AUTHZ_DB_PORT", "")
	t.Setenv("KIBAN_AUTHZ_DB_NAME", "")

	err := run(context.Background(), testLogger(), false)
	if err != nil {
		t.Fatalf("run: want nil (authz pool skipped, everything else converges), got %v", err)
	}
}

// TestRun_FullSuccess_ConvergesAgainstLiveStack is the full-wiring proof: real config, real
// Postgres (the owner role plus all three optional per-service pools), a real Preflight
// (Postgres + a real Keycloak realm-discovery fetch), a real (idempotent, no-op on this
// already-migrated stack) Migrations step including the real set-role-passwords.sh subprocess, a
// real RealmStep/Superadmin/Seed/Verify pass (every sub-step converge-if-different against
// state a prior real bootstrap run already created — see setBootstrapEnv's own comment) under
// the real Postgres advisory lock, returning nil.
func TestRun_FullSuccess_ConvergesAgainstLiveStack(t *testing.T) {
	setBootstrapEnv(t)

	err := run(context.Background(), testLogger(), false)
	if err != nil {
		t.Fatalf("run: want nil (full convergence against the already-bootstrapped dev stack), got %v", err)
	}
}

// TestRun_RegistryServicePool_ConnectErrorWrapped and TestRun_AuthzServicePool_ConnectErrorWrapped
// prove optionalServicePool's error branch is checked at EACH of its three call sites in run()
// (identity/registry/authz each has its own "if err != nil { return err }" — three separate
// statements even though they share one helper function), not just the identity one already
// covered above.
func TestRun_RegistryServicePool_ConnectErrorWrapped(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_REGISTRY_DB_PORT", "not-a-port")

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for a malformed registry-service DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to registry database") {
		t.Errorf("err = %v, want it to wrap \"connect to registry database\"", err)
	}
}

func TestRun_AuthzServicePool_ConnectErrorWrapped(t *testing.T) {
	setBootstrapEnv(t)
	t.Setenv("KIBAN_AUTHZ_DB_PORT", "not-a-port")

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error for a malformed authz-service DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to authz database") {
		t.Errorf("err = %v, want it to wrap \"connect to authz database\"", err)
	}
}

// TestRun_StepFailureSurfacesFromRunner proves run()'s final error branch: when every pool/DB
// step succeeds but a Step itself fails (here, PreflightStep's realm-discovery fetch against a
// URL that returns 404, never a valid OpenID discovery document), runner.Run's error propagates
// out of the WithAdvisoryLock closure and becomes run()'s own return value — not swallowed, not
// panicked.
func TestRun_StepFailureSurfacesFromRunner(t *testing.T) {
	setBootstrapEnv(t)
	kcHostPort := testEnv(t, "KEYCLOAK_HOST_PORT")
	t.Setenv("KEYCLOAK_REALM_DISCOVERY_URL", "http://127.0.0.1:"+kcHostPort+"/realms/does-not-exist/.well-known/openid-configuration")

	err := run(context.Background(), testLogger(), false)
	if err == nil {
		t.Fatal("run: want error when a step fails, got nil")
	}
	if !strings.Contains(err.Error(), "preflight") {
		t.Errorf("err = %v, want it to mention the failing step (preflight)", err)
	}
}
