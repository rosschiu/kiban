// SPDX-License-Identifier: Apache-2.0

package livestack

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The shared DB test environment every integration-tested package used to carry its own copy
// of: read a config value with the process environment taking priority over the env
// file, and open a pgx pool as a given role against the stack that config names. The
// "process env first" precedence is what lets `make test`'s `set -a; . .env.test; set +a`
// redirect every package's tests at the isolated stack; TargetsLiveStack is the interlock that
// refuses when nothing redirected them away from a PUBLIC live stack.

// Env returns name from the process environment, falling back to .env. It refuses (t.Fatal)
// when the resulting target would be the live stack in PUBLIC mode.
func Env(t testing.TB, name string) string {
	t.Helper()
	refuseLive(t)
	return envFrom(t, liveEnvPath(), name)
}

func refuseLive(t testing.TB) {
	t.Helper()
	if TargetsLiveStack() {
		t.Fatal(RefusalMessage)
	}
}

// TestStackEnv is Env for the live proofs that deliberately target kiban-test: the fallback file
// is .env.test (written by `make test-stack-up`), so it never resolves to the public
// stack and needs no refusal guard.
func TestStackEnv(t testing.TB, name string) string {
	t.Helper()
	return envFrom(t, liveEnvPath()+".test", name)
}

func envFrom(t testing.TB, envPath, name string) string {
	t.Helper()
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Fatalf("dbtest: open %s: %v (is the stack configured? see .env.example; `make test-stack-up` writes .env.test)", envPath, err)
	}
	if v := liveEnvValueAt(envPath, name); v != "" {
		return v
	}
	t.Fatalf("dbtest: %s not set (in the environment or %s)", name, envPath)
	return ""
}

// Pool connects as user/password to the test stack's Postgres (127.0.0.1:POSTGRES_HOST_PORT,
// database POSTGRES_DB, both via Env), pings it, and closes it in t.Cleanup. params are extra
// DSN query parameters (e.g. "pool_max_conns=16").
func Pool(t testing.TB, user, password string, params ...string) *pgxpool.Pool {
	t.Helper()
	refuseLive(t)
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		user, password, Env(t, "POSTGRES_HOST_PORT"), Env(t, "POSTGRES_DB"))
	for _, p := range params {
		dsn += "&" + p
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("dbtest: connect as %s: %v", user, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("dbtest: ping as %s: %v (is the test stack up and migrated? `make test-stack-up`)", user, err)
	}
	return pool
}

// AdminPool is Pool as the app-DB owner (kiban — it owns every schema, so it can
// truncate/reset fixtures across services) — never the Postgres superuser.
func AdminPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	return Pool(t, "kiban", Env(t, "KIBAN_DB_PASSWORD"))
}
