// SPDX-License-Identifier: Apache-2.0

// Package dbrole sets database role passwords over the wire, as the application-database
// owner `kiban` (which holds ADMIN OPTION on every role its migrations created). Deliberately
// not a migration: migrations are immutable and checksummed and must never embed a secret.
// ALTER ROLE ... PASSWORD is idempotent, so callers run it on every migrate and bootstrap.
package dbrole

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"
)

// Beginner is the slice of pgx.Conn and pgxpool.Pool this package needs.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// SetPasswords sets every role's password in ONE transaction, so a set is never half-rotated:
// either every ALTER applied or none did. Values travel as parameters (never spliced into
// SQL): each pair is handed to the server through set_config and read back inside a DO block,
// the only way ALTER ROLE takes a value it cannot bind.
func SetPasswords(ctx context.Context, db Beginner, passwords map[string]string) error {
	if len(passwords) == 0 {
		return nil
	}
	roles := make([]string, 0, len(passwords))
	for role, pw := range passwords {
		if !roleName.MatchString(role) {
			return fmt.Errorf("dbrole: invalid role name %q", role)
		}
		if pw == "" {
			return fmt.Errorf("dbrole: empty password for role %q", role)
		}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("dbrole: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	for _, role := range roles {
		if _, err := tx.Exec(ctx, `SELECT set_config('kiban.role_name', $1, true), set_config('kiban.role_password', $2, true)`, role, passwords[role]); err != nil {
			return fmt.Errorf("dbrole: stage %s: %w", role, err)
		}
		if _, err := tx.Exec(ctx, `DO $$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L', current_setting('kiban.role_name'), current_setting('kiban.role_password')); END $$`); err != nil {
			return fmt.Errorf("dbrole: alter role %s: %w", role, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("dbrole: commit: %w", err)
	}
	return nil
}
