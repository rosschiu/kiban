// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
)

// run() is exercised against the real dev stack (Postgres + Keycloak): neither is
// mocked here.

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// setIdentityEnv sets every env var run()'s config.Spec reads to real dev-stack values
// (host-run, not compose — 127.0.0.1:<POSTGRES_HOST_PORT>, kiban_identity's own role, and the
// real host-published Keycloak at 127.0.0.1:<KEYCLOAK_HOST_PORT> for the JWKS fetch
// NewTokenVerifier performs at startup).
func setIdentityEnv(t *testing.T) {
	t.Helper()
	realm := testEnv(t, "KEYCLOAK_REALM")
	kcHostPort := testEnv(t, "KEYCLOAK_HOST_PORT")
	env := map[string]string{
		"KIBAN_LISTEN_ADDR":               "127.0.0.1",
		"KIBAN_IDENTITY_DB_HOST":          "127.0.0.1",
		"KIBAN_IDENTITY_DB_PORT":          testEnv(t, "POSTGRES_HOST_PORT"),
		"KIBAN_IDENTITY_DB_NAME":          testEnv(t, "POSTGRES_DB"),
		"KIBAN_IDENTITY_DB_PASSWORD":      testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD"),
		"KEYCLOAK_BASE_URL":               "http://127.0.0.1:" + kcHostPort,
		"KEYCLOAK_JWKS_URL":               "http://127.0.0.1:" + kcHostPort + "/realms/" + realm + "/protocol/openid-connect/certs",
		"KEYCLOAK_ISSUER_URL":             "http://127.0.0.1:" + kcHostPort + "/realms/" + realm,
		"KEYCLOAK_REALM":                  realm,
		"KEYCLOAK_AUDIENCE":               "kiban-api",
		"KEYCLOAK_IDENTITY_CLIENT_SECRET": testEnv(t, "KEYCLOAK_IDENTITY_CLIENT_SECRET"),
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
		"KIBAN_LISTEN_ADDR", "KIBAN_IDENTITY_DB_HOST", "KIBAN_IDENTITY_DB_PORT",
		"KIBAN_IDENTITY_DB_NAME", "KIBAN_IDENTITY_DB_PASSWORD",
		"KEYCLOAK_BASE_URL", "KEYCLOAK_JWKS_URL", "KEYCLOAK_ISSUER_URL", "KEYCLOAK_REALM",
		"KEYCLOAK_AUDIENCE", "KEYCLOAK_IDENTITY_CLIENT_SECRET",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("KIBAN_IDENTITY_DB_PORT", "5432")
	t.Setenv("KIBAN_IDENTITY_DB_NAME", "kiban")
	// KIBAN_IDENTITY_DB_PASSWORD and the KEYCLOAK_* required fields intentionally left unset.

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("err = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_DBUnreachableErrors proves run() fails fast (wrapped "ping database") when the
// configured Postgres host is unreachable — no Keycloak call, no listener, is ever attempted.
func TestRun_DBUnreachableErrors(t *testing.T) {
	setIdentityEnv(t)
	t.Setenv("KIBAN_IDENTITY_DB_HOST", "127.0.0.1")
	t.Setenv("KIBAN_IDENTITY_DB_PORT", "1") // reserved/unlisted port — connection refused

	err := run(context.Background(), testLogger())
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
	setIdentityEnv(t)
	t.Setenv("KIBAN_IDENTITY_DB_PORT", "not-a-port") // fails DSN URL parsing inside pgxpool.New

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for a malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to database") {
		t.Errorf("err = %v, want it to wrap \"connect to database\"", err)
	}
}

// TestRun_TokenVerifierBuildErrors proves the "build token verifier" failure branch: an
// unreachable JWKS URL fails NewTokenVerifier's initial fetch, and run() surfaces it wrapped
// (matching the same "must not start serving without a working verifier" contract token.go's
// own doc comment states).
func TestRun_TokenVerifierBuildErrors(t *testing.T) {
	setIdentityEnv(t)
	t.Setenv("KEYCLOAK_JWKS_URL", "http://127.0.0.1:1/certs") // unreachable

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an unreachable JWKS endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "build token verifier") {
		t.Errorf("err = %v, want it to wrap \"build token verifier\"", err)
	}
}

// TestRun_StartsAndShutsDownGracefully is the full-wiring proof: real config, real Postgres
// (kiban_identity's own runtime role), a real Keycloak JWKS fetch, a real Service, a
// real HTTP listener actually accepting a request, and a clean graceful shutdown when ctx is
// cancelled.
func TestRun_StartsAndShutsDownGracefully(t *testing.T) {
	setIdentityEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, testLogger()) }()

	addr := "http://127.0.0.1:" + listenPort + "/api/health"
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("identity never came up at %s: %v", addr, lastErr)
	}

	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of ctx cancellation — graceful shutdown hung")
	}
}

// TestRun_ListenAddrConflictErrors proves the final select's "serveErr" branch: a second run()
// bound to an address a first, still-live run() already holds fails via ListenAndServe's own
// "address already in use" error, surfaced as run()'s return value.
func TestRun_ListenAddrConflictErrors(t *testing.T) {
	setIdentityEnv(t)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstErr := make(chan error, 1)
	go func() { firstErr <- run(firstCtx, testLogger()) }()

	addr := "http://127.0.0.1:" + listenPort + "/api/health"
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			resp.Body.Close()
			up = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Fatal("first run() never came up — cannot prove the conflict")
	}

	secondErr := run(context.Background(), testLogger())
	if secondErr == nil {
		t.Fatal("run: want error for a listen-address conflict, got nil")
	}

	firstCancel()
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first run(): want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first run() did not return within 10s of ctx cancellation")
	}
}
