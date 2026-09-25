// SPDX-License-Identifier: Apache-2.0

// Command bootstrap runs kiban-bootstrap: the one-shot container that converges a deployment.
// It wires an ordered Step runner (internal/bootstrap), serialized by a Postgres advisory lock:
// Preflight, Migrations, RealmStep (Keycloak realm reconciliation, kiban-api/kiban-frontend
// clients, MFA flow wiring, identity service-account exact-role verification, per-service
// secrets), SuperadminStep (one-time superadmin), SeedStep (registry modules + structural authz
// tuples), and VerifyStep (re-reads everything seeded). It runs as the bootstrap service in
// infra/compose.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/bootstrap"
	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/obs"
)

func main() {
	logger := obs.New("bootstrap")

	rotateSecrets := flag.Bool("rotate-secrets", false, "regenerate every managed Keycloak client secret via the admin API instead of reusing the current one")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, *rotateSecrets); err != nil {
		logger.Error("bootstrap: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-bootstrap end to end (config -> DB -> per-service pools -> ordered Step runner
// under an advisory lock), returning once every step has run. ctx is a parameter (not created
// here) so tests can drive it deterministically without relying on OS signals — main's own ctx
// still comes from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger, rotateSecrets bool) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_DB_PORT", Required: true},
		{Name: "POSTGRES_DB", Required: true},
		// The app-DB owner role `kiban` (non-superuser; infra/postgres-init/02-kiban-owner.sh):
		// bootstrap writes across schemas (identity + authz + audit) in one transaction, which
		// only the owner can. The name is fixed by the migrations' `AUTHORIZATION kiban`.
		{Name: "KIBAN_DB_PASSWORD", Required: true},

		{Name: "KIBAN_REGISTRY_DB_PASSWORD", Required: true},
		{Name: "KIBAN_IDENTITY_DB_PASSWORD", Required: true},
		{Name: "KIBAN_ORG_DB_PASSWORD", Required: true},
		{Name: "KIBAN_AUTHZ_DB_PASSWORD", Required: true},

		// Optional: an empty value skips the corresponding Preflight check (dev/test escape
		// hatch — production compose wiring always sets both).
		{Name: "KEYCLOAK_MANAGEMENT_URL", Default: ""},
		{Name: "KEYCLOAK_REALM_DISCOVERY_URL", Default: ""},

		{Name: "KIBAN_REPO_ROOT", Default: "/src"}, // infra/Dockerfile.service's WORKDIR (matches infra/migrate-entrypoint.sh's `cd /src`)
		{Name: "KIBAN_MIGRATIONS_ROOT", Default: "/src/migrations"},
		{Name: "KIBAN_SET_ROLE_PASSWORDS_SCRIPT", Default: "/src/migrations/registry/set-role-passwords.sh"},

		// --- realm reconciliation + service accounts ---
		// Optional: an empty KeycloakAdminBaseURL skips RealmStep entirely (test-only escape
		// hatch — production compose wiring always sets it).
		{Name: "KEYCLOAK_ADMIN_BASE_URL", Default: ""}, // e.g. http://keycloak:8080
		{Name: "KEYCLOAK_REALM", Default: "kiban"},
		{Name: "KC_BOOTSTRAP_ADMIN_USERNAME", Default: ""},
		{Name: "KC_BOOTSTRAP_ADMIN_PASSWORD", Default: ""},
		{Name: "KIBAN_DOMAIN", Default: ""},
		{Name: "KEYCLOAK_IDENTITY_CLIENT_SECRET", Default: ""},
		{Name: "KIBAN_SECRETS_DIR", Default: ""}, // e.g. /run/kiban-secrets

		// --- superadmin + seed ---
		{Name: "KIBAN_SUPERADMIN_USERNAME", Default: "superadmin"},
		{Name: "KIBAN_SUPERADMIN_EMAIL", Default: ""},
		{Name: "KIBAN_INSTALLED_MODULES", Default: ""},

		{Name: "KIBAN_REGISTRY_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_REGISTRY_DB_PORT", Default: ""},
		{Name: "KIBAN_REGISTRY_DB_NAME", Default: ""},
		{Name: "KIBAN_AUTHZ_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_AUTHZ_DB_PORT", Default: ""},
		{Name: "KIBAN_AUTHZ_DB_NAME", Default: ""},
		{Name: "KIBAN_ORG_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_ORG_DB_PORT", Default: ""},
		{Name: "KIBAN_ORG_DB_NAME", Default: ""},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// KIBAN_SUPERADMIN_PASSWORD supports the *_FILE convention like every other secret
	// (secrets are never stored in env-visible places) — config.Load's *_FILE lookup
	// keys off the field name, so this is loaded as its own small Spec.
	superadminPassword, err := config.Load(config.Spec{{Name: "KIBAN_SUPERADMIN_PASSWORD", Default: ""}})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	values["KIBAN_SUPERADMIN_PASSWORD"] = superadminPassword["KIBAN_SUPERADMIN_PASSWORD"]

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		"kiban", values["KIBAN_DB_PASSWORD"],
		values["KIBAN_DB_HOST"], values["KIBAN_DB_PORT"], values["POSTGRES_DB"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	// Per-service runtime-role pools (kiban_registry/kiban_authz/kiban_org) — connecting
	// as each service's OWN role, never the migration-owner, matching every
	// service's own cmd/*/main.go. Empty *_DB_PORT skips that pool (test-only escape hatch;
	// production compose wiring always sets all three).
	registryPool, err := optionalServicePool(ctx, "registry", "kiban_registry", values["KIBAN_REGISTRY_DB_PASSWORD"], values, "KIBAN_REGISTRY_DB_HOST", "KIBAN_REGISTRY_DB_PORT", "KIBAN_REGISTRY_DB_NAME")
	if err != nil {
		return err
	}
	if registryPool != nil {
		defer registryPool.Close()
	}
	authzPool, err := optionalServicePool(ctx, "authz", "kiban_authz", values["KIBAN_AUTHZ_DB_PASSWORD"], values, "KIBAN_AUTHZ_DB_HOST", "KIBAN_AUTHZ_DB_PORT", "KIBAN_AUTHZ_DB_NAME")
	if err != nil {
		return err
	}
	if authzPool != nil {
		defer authzPool.Close()
	}
	// OrgPool for MemberMappedUserBackfill (see seed.go / member_mapped_user_backfill.go).
	orgPool, err := optionalServicePool(ctx, "org", "kiban_org", values["KIBAN_ORG_DB_PASSWORD"], values, "KIBAN_ORG_DB_HOST", "KIBAN_ORG_DB_PORT", "KIBAN_ORG_DB_NAME")
	if err != nil {
		return err
	}
	if orgPool != nil {
		defer orgPool.Close()
	}

	deps := &bootstrap.Deps{
		Logger:     logger,
		Pool:       pool,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},

		KeycloakManagementURL:     values["KEYCLOAK_MANAGEMENT_URL"],
		KeycloakRealmDiscoveryURL: values["KEYCLOAK_REALM_DISCOVERY_URL"],

		RepoRoot:       values["KIBAN_REPO_ROOT"],
		MigrationsRoot: values["KIBAN_MIGRATIONS_ROOT"],
		DBEnv: map[string]string{
			"KIBAN_DB_HOST":     values["KIBAN_DB_HOST"],
			"KIBAN_DB_PORT":     values["KIBAN_DB_PORT"],
			"POSTGRES_DB":       values["POSTGRES_DB"],
			"KIBAN_DB_PASSWORD": values["KIBAN_DB_PASSWORD"],
		},
		RolePasswords: map[string]string{
			"registry": values["KIBAN_REGISTRY_DB_PASSWORD"],
			"identity": values["KIBAN_IDENTITY_DB_PASSWORD"],
			"org":      values["KIBAN_ORG_DB_PASSWORD"],
			"authz":    values["KIBAN_AUTHZ_DB_PASSWORD"],
		},
		SetRolePasswordsScript: values["KIBAN_SET_ROLE_PASSWORDS_SCRIPT"],

		KeycloakAdminBaseURL:     values["KEYCLOAK_ADMIN_BASE_URL"],
		KeycloakRealm:            values["KEYCLOAK_REALM"],
		KCBootstrapAdminUsername: values["KC_BOOTSTRAP_ADMIN_USERNAME"],
		KCBootstrapAdminPassword: values["KC_BOOTSTRAP_ADMIN_PASSWORD"],
		KibanDomain:              values["KIBAN_DOMAIN"],
		IdentityClientSecret:     values["KEYCLOAK_IDENTITY_CLIENT_SECRET"],
		SecretsDir:               values["KIBAN_SECRETS_DIR"],
		RotateSecrets:            rotateSecrets,

		SuperadminUsername: values["KIBAN_SUPERADMIN_USERNAME"],
		SuperadminEmail:    values["KIBAN_SUPERADMIN_EMAIL"],
		SuperadminPassword: values["KIBAN_SUPERADMIN_PASSWORD"],

		RegistryPool:        registryPool,
		AuthzPool:           authzPool,
		OrgPool:             orgPool,
		InstalledModulesCSV: values["KIBAN_INSTALLED_MODULES"],
	}

	// Order: preflight → migrations → realm reconciliation → (service accounts + secrets are
	// RealmStep's own last sub-step) → one-time superadmin → seed → verify (read-only
	// close-out step).
	steps := []bootstrap.Step{
		bootstrap.PreflightStep{},
		bootstrap.MigrationsStep{},
		bootstrap.RealmStep{},
		bootstrap.SuperadminStep{},
		bootstrap.SeedStep{},
		bootstrap.VerifyStep{},
	}
	runner := &bootstrap.Runner{Steps: steps}

	return bootstrap.WithAdvisoryLock(ctx, pool, func(ctx context.Context) error {
		results, err := runner.Run(ctx, deps)
		for _, res := range results {
			logger.Info("bootstrap: step result",
				slog.String("step", res.Step), slog.String("outcome", string(res.Outcome)), slog.String("detail", res.Detail))
		}
		if err != nil {
			return err
		}
		logger.Info("bootstrap: run complete")
		return nil
	})
}

// optionalServicePool connects to one service's own database as its own runtime role,
// returning (nil, nil) when portKey's value is empty — the test-only escape hatch every other
// optional Deps field in this file already uses; production compose wiring always sets all
// three (host/port/name) keys per service.
func optionalServicePool(ctx context.Context, service, role, password string, values map[string]string, hostKey, portKey, nameKey string) (*pgxpool.Pool, error) {
	if values[portKey] == "" || values[nameKey] == "" {
		return nil, nil
	}
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		role, password, values[hostKey], values[portKey], values[nameKey],
	)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to %s database as %s: %w", service, role, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping %s database as %s: %w", service, role, err)
	}
	return pool, nil
}
