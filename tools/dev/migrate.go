// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/dbrole"
)

// migrationTree is one tern tree and the roles whose passwords are set right after it.
type migrationTree struct {
	name  string
	dir   string
	roles map[string]string // role -> environment variable holding its password
}

// migrationTrees is the one order that matters: registry first (it creates the per-service
// roles and shared schemas every later migration grants against), authz before identity
// (authz/0010 backfills the superadmin tuples identity/0005 needs before it drops
// identity.platform_role), then org, then the sample modules. internal/bootstrap's
// MigrationServiceOrder is the same list for the foundation.
var migrationTrees = []migrationTree{
	{"registry", "migrations/registry", map[string]string{
		"kiban_registry": "KIBAN_REGISTRY_DB_PASSWORD", "kiban_identity": "KIBAN_IDENTITY_DB_PASSWORD",
		"kiban_org": "KIBAN_ORG_DB_PASSWORD", "kiban_authz": "KIBAN_AUTHZ_DB_PASSWORD"}},
	{"authz", "migrations/authz", nil},
	{"identity", "migrations/identity", nil},
	{"org", "migrations/org", nil},
	{"notification", "modules/notification/migrations", map[string]string{"kiban_notification": "KIBAN_NOTIFICATION_DB_PASSWORD"}},
	{"timesheet", "modules/timesheet/migrations", map[string]string{"kiban_timesheet": "KIBAN_TIMESHEET_DB_PASSWORD"}},
	{"docs", "modules/docs/migrations", map[string]string{"kiban_docs": "KIBAN_DOCS_DB_PASSWORD"}},
	{"helpdesk", "modules/helpdesk/migrations", map[string]string{"kiban_helpdesk": "KIBAN_HELPDESK_DB_PASSWORD"}},
}

// runMigrate is the compose/Kubernetes `migrate` job and `make migrate-<tree>`: every tree's
// tern migrations in order, each followed by its role-password step, all as the app-DB owner
// `kiban` (KIBAN_DB_PASSWORD), never the superuser. Connection: KIBAN_DB_HOST (default
// postgres, the compose service) and KIBAN_DB_PORT (default 5432); `make migrate-*` passes the
// host-published port. --only <tree> runs one tree and its password step.
func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	only := fs.String("only", "", "run one tree only (registry|authz|identity|org|notification|timesheet|docs|helpdesk)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	host := envOr("KIBAN_DB_HOST", "postgres")
	port := envOr("KIBAN_DB_PORT", "5432")
	dbName, ownerPW := os.Getenv("POSTGRES_DB"), os.Getenv("KIBAN_DB_PASSWORD")
	if dbName == "" || ownerPW == "" {
		return fail("migrate", fmt.Errorf("POSTGRES_DB and KIBAN_DB_PASSWORD must be set"))
	}
	env := []string{"KIBAN_DB_HOST=" + host, "KIBAN_DB_PORT=" + port}
	trees := migrationTrees
	if *only != "" {
		trees = nil
		for _, t := range migrationTrees {
			if t.name == *only {
				trees = []migrationTree{t}
			}
		}
		if trees == nil {
			return fail("migrate", fmt.Errorf("unknown tree %q", *only))
		}
	}
	// Every password must be present before the first migration runs: never a half-rotated set.
	for _, t := range trees {
		for role, v := range t.roles {
			if os.Getenv(v) == "" {
				return fail("migrate", fmt.Errorf("%s (password for role %s) is not set", v, role))
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	dsn := fmt.Sprintf("postgres://kiban:%s@%s:%s/%s?sslmode=disable", url.QueryEscape(ownerPW), host, port, url.PathEscape(dbName))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fail("migrate", fmt.Errorf("connect as kiban: %w", err))
	}
	defer conn.Close(ctx)
	for _, t := range trees {
		fmt.Printf("migrate: applying %s migrations\n", t.name)
		if err := run("", env, "go", "tool", "tern", "migrate", "-m", t.dir, "-c", t.dir+"/tern.conf"); err != nil {
			return fail("migrate", fmt.Errorf("%s: tern: %w", t.name, err))
		}
		if len(t.roles) == 0 {
			continue
		}
		passwords := map[string]string{}
		names := make([]string, 0, len(t.roles))
		for role, v := range t.roles {
			passwords[role] = os.Getenv(v)
			names = append(names, role)
		}
		if err := dbrole.SetPasswords(ctx, conn, passwords); err != nil {
			return fail("migrate", fmt.Errorf("%s: %w", t.name, err))
		}
		fmt.Printf("migrate: set role password(s): %s\n", strings.Join(names, ", "))
	}
	fmt.Println("migrate: all migrations applied")
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
