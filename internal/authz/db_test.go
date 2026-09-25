// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"testing"
)

// TestCheckMigrationsApplied proves the real dev stack's authz database has migrations applied
// (the success path db.go exists to gate on) — the error path (a database with NO
// schema_version_authz row, or version<=0) would require standing up a second, unmigrated
// database, which is out of scope for this behavioral suite; that branch is exercised in
// practice by `make dev` on a fresh stack failing loudly if migrations are missing.
func TestCheckMigrationsApplied(t *testing.T) {
	pool := authzPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("CheckMigrationsApplied on the live migrated dev stack: %v", err)
	}
}
