// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// adminPool connects as the migration-owner role (kiban) — used only to set up/tear down test
// fixtures the runtime role (kiban_authz) has no DDL/cross-row-reset rights to perform.
func adminPool(t *testing.T) *pgxpool.Pool { return livestack.AdminPool(t) }

// authzPool connects as kiban_authz — the real runtime role — so tests exercise the
// actual grants the service will run with in production.
func authzPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_authz", testEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
}
