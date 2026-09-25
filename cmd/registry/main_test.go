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
	"github.com/rosschiu/kiban/internal/registry"
)

// This package's own copy of the small dbtest env-loading helper every other integration-tested
// package duplicates rather than shares (see internal/identity/dbtest_test.go's header comment).
// run() is exercised against the real dev stack: service-boundary code gets an integration proof,
// and Postgres is not a genuinely external system, so it is never mocked here.

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// setRegistryEnv sets every env var run()'s config.Spec reads to real dev-stack values
// (host-run, not compose — 127.0.0.1:<POSTGRES_HOST_PORT>, kiban_registry's own role) and
// returns a cleanup that restores the pre-test environment exactly, via t.Cleanup semantics.
func setRegistryEnv(t *testing.T) {
	t.Helper()
	env := map[string]string{
		"KIBAN_LISTEN_ADDR":          "127.0.0.1",
		"KIBAN_REGISTRY_DB_HOST":     "127.0.0.1",
		"KIBAN_REGISTRY_DB_PORT":     testEnv(t, "POSTGRES_HOST_PORT"),
		"KIBAN_REGISTRY_DB_NAME":     testEnv(t, "POSTGRES_DB"),
		"KIBAN_REGISTRY_DB_PASSWORD": testEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"),
		"KIBAN_INSTALLED_MODULES":    "",
		"KIBAN_AUTHZ_BASE_URL":       "http://127.0.0.1:1", // unreachable on purpose — never called at startup, only lazily on admin mutations
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
	// Explicitly unset every var run()'s Spec might otherwise pick up from a parent test/shell,
	// then set only an incomplete subset (missing KIBAN_REGISTRY_DB_PASSWORD, Required: true).
	for _, k := range []string{
		"KIBAN_LISTEN_ADDR", "KIBAN_REGISTRY_DB_HOST", "KIBAN_REGISTRY_DB_PORT",
		"KIBAN_REGISTRY_DB_NAME", "KIBAN_REGISTRY_DB_PASSWORD",
		"KIBAN_INSTALLED_MODULES", "KIBAN_AUTHZ_BASE_URL",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("KIBAN_REGISTRY_DB_PORT", "5432")
	t.Setenv("KIBAN_REGISTRY_DB_NAME", "kiban")
	// KIBAN_REGISTRY_DB_PASSWORD intentionally left unset.

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("err = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_DBUnreachableErrors proves run() fails fast (wrapped "connect to database" or
// "ping database") when the configured Postgres host is unreachable — no listener is ever
// started.
func TestRun_DBUnreachableErrors(t *testing.T) {
	setRegistryEnv(t)
	t.Setenv("KIBAN_REGISTRY_DB_HOST", "127.0.0.1")
	t.Setenv("KIBAN_REGISTRY_DB_PORT", "1") // reserved/unlisted port — connection refused

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an unreachable database, got nil")
	}
	if !strings.Contains(err.Error(), "database") {
		t.Errorf("err = %v, want it to mention the database step", err)
	}
}

// TestRun_DBDSNMalformedErrors proves the OTHER database-step failure branch: pgxpool.New itself
// rejecting a malformed DSN (never even attempting a connection) is a distinct code path from
// TestRun_DBUnreachableErrors's Ping failure — both wrap "connect to database"/"database" but
// New's own validation fires first.
func TestRun_DBDSNMalformedErrors(t *testing.T) {
	setRegistryEnv(t)
	t.Setenv("KIBAN_REGISTRY_DB_PORT", "not-a-port") // fails DSN URL parsing inside pgxpool.New

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for a malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to database") {
		t.Errorf("err = %v, want it to wrap \"connect to database\"", err)
	}
}

// TestRun_SeedErrors proves the store.Seed failure branch: an invalid module key in
// builtinModules (same package, so this test can set it directly — restored via t.Cleanup so it
// never leaks into TestRun_StartsAndShutsDownGracefully's real zero-module seed) fails
// moduleKeyPattern validation inside Store.Seed, before any catalog row is written.
func TestRun_SeedErrors(t *testing.T) {
	setRegistryEnv(t)

	original := builtinModules
	builtinModules = []registry.ModuleManifest{{ModuleKey: "not a valid key!!"}}
	t.Cleanup(func() { builtinModules = original })

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an invalid builtin module key, got nil")
	}
	if !strings.Contains(err.Error(), "seed registry") {
		t.Errorf("err = %v, want it to wrap \"seed registry\"", err)
	}
}

// TestRun_StartsAndShutsDownGracefully is the full-wiring proof: real config, real Postgres
// (kiban_registry's own runtime role), a real Seed() + Service, a real HTTP listener
// actually accepting a request, and a clean graceful shutdown when ctx is cancelled — the same
// shape production's signal.NotifyContext cancellation drives, just triggered deterministically
// instead of by a real OS signal.
func TestRun_StartsAndShutsDownGracefully(t *testing.T) {
	setRegistryEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, testLogger()) }()

	// Poll the real fixed listen address (127.0.0.1:8110 — not published by the compose stack
	// to the host, so a host-run test process is free to bind it) until the server answers.
	addr := "http://127.0.0.1:" + listenPort + "/api/health"
	deadline := time.Now().Add(10 * time.Second)
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
		t.Fatalf("registry never came up at %s: %v", addr, lastErr)
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
// "address already in use" error, surfaced as run()'s return value — not a hang, not a panic.
func TestRun_ListenAddrConflictErrors(t *testing.T) {
	setRegistryEnv(t)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstErr := make(chan error, 1)
	go func() { firstErr <- run(firstCtx, testLogger()) }()

	addr := "http://127.0.0.1:" + listenPort + "/api/health"
	deadline := time.Now().Add(10 * time.Second)
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
