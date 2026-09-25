// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (ARCH-004: no runtime DDL, ever; migrations are applied out-of-band by `make migrate-authz`,
// as the kiban owner role). Same pattern as internal/org/store.go and internal/registry/store.go.
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_authz`).Scan(&version)
	if err != nil {
		return fmt.Errorf(
			"authz: migrations not applied (run `make migrate-authz` against this database first): %w",
			err,
		)
	}
	if version <= 0 {
		return errors.New("authz: migrations table present but at version 0 — run `make migrate-authz`")
	}
	return nil
}
