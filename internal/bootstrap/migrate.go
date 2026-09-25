// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jackc/pgx/v5"
)

// MigrationServiceOrder is the real dependency order tern migrations must run in: registry
// FIRST, because migrations/registry/0001_roles.sql creates the four per-service DB roles
// (kiban_registry/kiban_identity/kiban_org/kiban_authz) that identity's own
// migrations/identity/0001_schema.sql immediately GRANTs USAGE to — running identity before
// registry fails outright ("role kiban_identity does not exist"); authz BEFORE identity, because
// migrations/authz/0010 backfills the superadmin tuples that migrations/identity/0005 requires
// before it drops identity.platform_role. This matches infra/migrate-entrypoint.sh (the compose
// migrate job's order).
var MigrationServiceOrder = []string{"registry", "authz", "identity", "org"}

// schemaVersionTable is each service's tern version_table (migrations/<service>/tern.conf).
var schemaVersionTable = map[string]string{
	"registry": "public.schema_version_registry",
	"identity": "public.schema_version_identity",
	"org":      "public.schema_version_org",
	"authz":    "public.schema_version_authz",
}

// MigrationsStep applies every service's tern migrations, in MigrationServiceOrder, as the
// owner role — then sets the four runtime role passwords (idempotent, ALTER ROLE) and spot-
// checks the per-service grant matrix: a runtime role can SELECT another service's PUBLISHED
// VIEW but not its base tables. Never runs DDL itself in Go — it only shells out to
// `go tool tern`, the same tool/config files `make migrate-*` already uses (migrations are the
// single source of schema truth, not bootstrap's own logic).
type MigrationsStep struct{}

func (MigrationsStep) Name() string { return "migrations" }

func (MigrationsStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	anyApplied := false
	var details []string

	for _, service := range MigrationServiceOrder {
		before, err := schemaVersion(ctx, deps.Pool, service)
		if err != nil {
			return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("migrations: %s: read version before: %w", service, err)
		}

		out, err := runTern(ctx, deps, service)
		if err != nil {
			return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("migrations: %s: tern migrate: %w (output: %s)", service, err, out)
		}

		after, err := schemaVersion(ctx, deps.Pool, service)
		if err != nil {
			return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("migrations: %s: read version after: %w", service, err)
		}

		if after > before {
			anyApplied = true
			details = append(details, fmt.Sprintf("%s: v%d->v%d applied", service, before, after))
		} else {
			details = append(details, fmt.Sprintf("%s: v%d converged", service, after))
		}

		if service == "registry" {
			if out, err := runSetRolePasswords(ctx, deps); err != nil {
				return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("migrations: set-role-passwords: %w (output: %s)", err, out)
			}
		}
	}

	if err := spotCheckGrantMatrix(ctx, deps); err != nil {
		return OutcomeFailed, strings.Join(details, "; "), fmt.Errorf("migrations: grant matrix spot-check: %w", err)
	}
	details = append(details, "grant matrix: OK (kiban_org can read identity.user_read_v, cannot read identity.user_account)")

	if anyApplied {
		return OutcomeApplied, strings.Join(details, "; "), nil
	}
	return OutcomeConverged, strings.Join(details, "; "), nil
}

func schemaVersion(ctx context.Context, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, service string) (int64, error) {
	table, ok := schemaVersionTable[service]
	if !ok {
		return 0, fmt.Errorf("unknown service %q", service)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil // fresh database — this service's version table doesn't exist yet
	}
	var version int64
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT version FROM %s`, table)).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func runTern(ctx context.Context, deps *Deps, service string) (string, error) {
	migDir := deps.MigrationsRoot + "/" + service
	confPath := migDir + "/tern.conf"

	cmd := exec.CommandContext(ctx, "go", "tool", "tern", "migrate", "-m", migDir, "-c", confPath)
	cmd.Dir = deps.RepoRoot
	cmd.Env = append(os.Environ(), envSlice(deps.DBEnv)...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func runSetRolePasswords(ctx context.Context, deps *Deps) (string, error) {
	env := map[string]string{}
	for k, v := range deps.DBEnv {
		env[k] = v
	}
	for _, service := range []string{"registry", "identity", "org", "authz"} {
		pw, ok := deps.RolePasswords[service]
		if !ok {
			return "", fmt.Errorf("no role password configured for %q", service)
		}
		env["KIBAN_"+strings.ToUpper(service)+"_DB_PASSWORD"] = pw
	}

	cmd := exec.CommandContext(ctx, deps.SetRolePasswordsScript)
	cmd.Dir = deps.RepoRoot
	cmd.Env = append(os.Environ(), envSlice(env)...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func envSlice(m map[string]string) []string {
	s := make([]string, 0, len(m))
	for k, v := range m {
		s = append(s, k+"="+v)
	}
	return s
}

// spotCheckGrantMatrix proves per-service role isolation: connect as one runtime role
// (kiban_org) and confirm it CAN SELECT another service's published view
// (identity.user_read_v, GRANTed by migrations/identity/0003_user_read_v.sql) but CANNOT SELECT
// that service's base table (identity.user_account) — a failed SELECT is the passing test.
func spotCheckGrantMatrix(ctx context.Context, deps *Deps) error {
	dsn := roleDSN(deps, "org")
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect as kiban_org: %w", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `SELECT 1 FROM identity.user_read_v LIMIT 0`); err != nil {
		return fmt.Errorf("kiban_org expected to SELECT identity.user_read_v (published view), got: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT 1 FROM identity.user_account LIMIT 0`); err == nil {
		return fmt.Errorf("kiban_org unexpectedly could SELECT identity.user_account (base table) — grant matrix violated")
	}
	return nil
}

func roleDSN(deps *Deps, service string) string {
	return fmt.Sprintf(
		"postgres://kiban_%s:%s@%s:%s/%s?sslmode=disable",
		service, deps.RolePasswords[service], deps.DBEnv["KIBAN_DB_HOST"], deps.DBEnv["KIBAN_DB_PORT"], deps.DBEnv["POSTGRES_DB"],
	)
}
