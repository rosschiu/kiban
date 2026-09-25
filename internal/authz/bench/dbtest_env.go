// SPDX-License-Identifier: Apache-2.0

//go:build bench

package bench

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/livestack"
)

// Integration tests in this package run against the isolated test stack through
// internal/livestack (env precedence, DSN, public-mode refusal).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// authzPool connects as kiban_authz with max conns >= 10 (one pgx pool sized for the
// concurrent batchCan worker pool of 8).
func authzPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_authz", testEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"), "pool_max_conns=16")
}
