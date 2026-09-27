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

// This package's own copy of the small dbtest env-loading helper every other integration-tested
// package duplicates rather than shares (see internal/identity/dbtest_test.go's header comment).
// run() is exercised against the real dev stack: service-boundary code gets an integration
// proof, and Postgres is never mocked here.

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// setOrgEnv sets every env var run()'s config.Spec reads to real dev-stack values (host-run, not
// compose — 127.0.0.1:<POSTGRES_HOST_PORT>, kiban_org's own role).
func setOrgEnv(t *testing.T) {
	t.Helper()
	env := map[string]string{
		"KIBAN_LISTEN_ADDR":       "127.0.0.1",
		"KIBAN_ORG_DB_HOST":       "127.0.0.1",
		"KIBAN_ORG_DB_PORT":       testEnv(t, "POSTGRES_HOST_PORT"),
		"KIBAN_ORG_DB_NAME":       testEnv(t, "POSTGRES_DB"),
		"KIBAN_ORG_DB_PASSWORD":   testEnv(t, "KIBAN_ORG_DB_PASSWORD"),
		"KIBAN_IDENTITY_BASE_URL": "http://127.0.0.1:1", // unreachable on purpose — never called at startup, only lazily on link-user requests
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
		"KIBAN_LISTEN_ADDR", "KIBAN_ORG_DB_HOST", "KIBAN_ORG_DB_PORT",
		"KIBAN_ORG_DB_NAME", "KIBAN_ORG_DB_PASSWORD",
		"KIBAN_IDENTITY_BASE_URL",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("KIBAN_ORG_DB_PORT", "5432")
	t.Setenv("KIBAN_ORG_DB_NAME", "kiban")
	// KIBAN_ORG_DB_PASSWORD intentionally left unset.

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("err = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_DBUnreachableErrors proves run() fails fast (wrapped "ping database") when the
// configured Postgres host is unreachable — no listener is ever started.
func TestRun_DBUnreachableErrors(t *testing.T) {
	setOrgEnv(t)
	t.Setenv("KIBAN_ORG_DB_HOST", "127.0.0.1")
	t.Setenv("KIBAN_ORG_DB_PORT", "1") // reserved/unlisted port — connection refused

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
	setOrgEnv(t)
	t.Setenv("KIBAN_ORG_DB_PORT", "not-a-port") // fails DSN URL parsing inside pgxpool.New

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for a malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "connect to database") {
		t.Errorf("err = %v, want it to wrap \"connect to database\"", err)
	}
}

// TestRun_StartsAndShutsDownGracefully is the full-wiring proof: real config, real Postgres
// (kiban_org's own runtime role), a real Service, a real HTTP listener actually
// accepting a request, and a clean graceful shutdown when ctx is cancelled.
func TestRun_StartsAndShutsDownGracefully(t *testing.T) {
	setOrgEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, testLogger()) }()

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
		t.Fatalf("org never came up at %s: %v", addr, lastErr)
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
	setOrgEnv(t)

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
