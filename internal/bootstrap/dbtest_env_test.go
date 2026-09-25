// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the real dev stack Postgres for the
// advisory-lock tests, and against ephemeral, throwaway Postgres containers (docker run) for
// the fresh-database migrations proof, since a genuinely fresh CLUSTER (not just a fresh
// database on the already-migrated dev cluster, whose roles already exist) is what the
// clean-deploy-from-migrations claim needs. The `bootstrap*` names are thin wrappers over
// internal/livestack.

// bootstrapRepoRoot resolves the repo root from this test file's own location — this file lives
// at <repoRoot>/internal/bootstrap/dbtest_env_test.go.
func bootstrapRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("dbtest: could not determine caller for repo root lookup")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// bootstrapTestEnv returns the value of name from the process environment, falling back to
// .env.
func bootstrapTestEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// bootstrapTestEnvOrDefault is bootstrapTestEnv without the Fatalf — used for values (like the
// gateway's TLS host port) that `make dev`'s .env has never needed to declare explicitly
// (compose.yaml hardcodes 8443) but the isolated test stack overrides via
// KIBAN_GATEWAY_TLS_HOST_PORT (.env.test) so live tests hit the isolated gateway, not the
// live one.
func bootstrapTestEnvOrDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// bootstrapAdminPool connects to the live dev stack as the migration-owner role (kiban) — used
// by the advisory-lock tests, which only need a real Postgres session to lock against, not a
// fresh database.
func bootstrapAdminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }
