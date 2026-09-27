// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"fmt"

	"github.com/rosschiu/kiban/internal/pgconv"
)

// SeedSuperadmin resolves-or-creates the identity.user_account row for the one-time platform
// superadmin inside the CALLER's transaction — internal/bootstrap's SuperadminStep, which runs as
// the owner role and writes the superadmin's one record (authz's `system:platform#superadmin`
// tuple, internal/authz/store.Grant) in the same transaction. Identity itself grants no role: it
// only guarantees the kcSub has a user row, so the tuple is never an orphan. Idempotent (same
// upsert as ResolveOrCreate).
func SeedSuperadmin(ctx context.Context, db DBTX, kcSub, email, preferredUsername string) (User, error) {
	row, err := New(db).UpsertUserAccount(ctx, UpsertUserAccountParams{
		KcSub: kcSub, Email: pgconv.StrOrNil(email), PreferredUsername: pgconv.StrOrNil(preferredUsername),
	})
	if err != nil {
		return User{}, fmt.Errorf("identity: seed superadmin: resolve-or-create: %w", err)
	}
	return userFromRow(row), nil
}
