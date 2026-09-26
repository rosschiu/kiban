// SPDX-License-Identifier: Apache-2.0

// Package bootstrap implements the kiban-bootstrap step runner: an ordered set of idempotent,
// individually-logged steps (preflight, migrations orchestration, realm reconciliation,
// service accounts, superadmin, seed, verify) that each report a truthful
// applied|converged|failed outcome. There is deliberately no "rolled back" outcome: a step
// that fails partway reports Failed with the real error,
// and whatever state it left behind stands — no step implementation may claim to have undone
// it.
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Outcome is one step's truthful result: applied, converged, or failed.
type Outcome string

const (
	// OutcomeApplied means the step changed real state to reach its target.
	OutcomeApplied Outcome = "applied"
	// OutcomeConverged means the step found its target state already satisfied — a no-op
	// re-run, the common case once a deployment has bootstrapped once.
	OutcomeConverged Outcome = "converged"
	// OutcomeFailed means the step did not reach its target state. Err is always non-nil.
	OutcomeFailed Outcome = "failed"
)

// Result is one step's reported outcome, in run order.
type Result struct {
	Step    string
	Outcome Outcome
	Detail  string
	Err     error
}

// Step is one ordered, idempotent bootstrap unit. Run must never partially apply changes and
// then report success — if it returns (OutcomeFailed, _, err), any state it already touched
// before failing is exactly what's left; nothing is (or claims to be) rolled back.
type Step interface {
	Name() string
	Run(ctx context.Context, deps *Deps) (Outcome, string, error)
}

// Deps bundles everything the ordered steps need.
type Deps struct {
	Logger *slog.Logger

	// Pool connects as the migration-owner role (`kiban`, the non-superuser app-DB
	// owner — infra/postgres-init/02-kiban-owner.sh) — the only role with DDL rights. Preflight pings it; MigrationsStep reads schema_version_*
	// tables through it (before/after comparisons never need elevated DDL, just SELECT);
	// SuperadminStep writes the one-time superadmin's identity row and platform-role tuple
	// through it in one transaction (the only role that may write both schemas); VerifyStep
	// re-counts the tuple through it.
	Pool *pgxpool.Pool

	HTTPClient *http.Client

	// KeycloakManagementURL is Keycloak's health endpoint base (management port, split from
	// the app port in this Keycloak version) — infra/bootstrap-stub/entrypoint.sh's own step 2
	// ported to Go. Empty skips the check (test-only escape hatch; production wiring always
	// sets it).
	KeycloakManagementURL string
	// KeycloakRealmDiscoveryURL is the realm's OIDC discovery document URL — a non-empty
	// issuer there proves the realm is actually imported (entrypoint.sh's step 3). Empty skips
	// the check.
	KeycloakRealmDiscoveryURL string

	// RepoRoot is the working directory `go tool tern` and set-role-passwords.sh run from (a
	// module-rooted directory so `go tool` resolves the go.mod tool directive).
	RepoRoot string
	// MigrationsRoot is the absolute path to the migrations/ directory (contains the
	// registry/identity/org/authz subdirectories, each with its own tern.conf).
	MigrationsRoot string
	// DBEnv is passed verbatim as extra environment to every tern/set-role-passwords.sh
	// subprocess: KIBAN_DB_HOST, KIBAN_DB_PORT, POSTGRES_DB, KIBAN_DB_PASSWORD (the owner
	// role's own connection info — tern.conf's own {{env "..."}} templates read
	// exactly these names).
	DBEnv map[string]string
	// RolePasswords maps service name ("registry"|"identity"|"org"|"authz") to its runtime
	// DB role's password — used both to drive set-role-passwords.sh (KIBAN_<SVC>_DB_PASSWORD)
	// and to open real (non-superuser) connections for the grant-matrix spot-check.
	RolePasswords map[string]string
	// SetRolePasswordsScript is the path to migrations/registry/set-role-passwords.sh.
	SetRolePasswordsScript string

	// --- realm reconciliation + service accounts ---

	// KeycloakAdminBaseURL is Keycloak's APP port base (e.g. "http://127.0.0.1:8081") — the
	// admin REST API lives under {base}/admin/realms/{realm}, token endpoint under
	// {base}/realms/master/... (master realm password grant; the master-realm bootstrap admin
	// is used only by bootstrap). Empty skips RealmStep entirely (test-only escape hatch).
	KeycloakAdminBaseURL string
	// KeycloakRealm is the app realm RealmStep reconciles (matches KEYCLOAK_REALM).
	KeycloakRealm string
	// KCBootstrapAdminUsername/Password are the master-realm bootstrap admin credentials
	// (KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD) — used ONLY by RealmStep/SuperadminStep, never
	// passed to any other service.
	KCBootstrapAdminUsername string
	KCBootstrapAdminPassword string
	// KibanDomain sources kiban-frontend's redirect URIs/web origins.
	// Empty falls back to the dev-loopback origins already in infra/keycloak-build/
	// realm-kiban.json (localhost:3000/5173/80), so a domainless dev run still converges.
	KibanDomain string
	// ServiceClients (KIBAN_SERVICE_CLIENTS, comma-separated client ids) are the confidential
	// service-account clients RealmStep creates for backends that need their own token.
	ServiceClients []string
	// IdentityClientSecret is the kiban-identity-service client's current secret
	// (KEYCLOAK_IDENTITY_CLIENT_SECRET) — RealmStep writes it to SecretsDir as a 0600 file;
	// with RotateSecrets it instead rotates the secret via the admin API first and writes the
	// NEW value (the operator must then update KEYCLOAK_IDENTITY_CLIENT_SECRET to match — see
	// this step's own detail/warning output).
	IdentityClientSecret string
	// SecretsDir is the shared volume directory per-service client secrets are written to as
	// 0600 files. Empty skips the write (test-only escape hatch).
	SecretsDir string
	// RotateSecrets is the --rotate-secrets flag: forces RealmStep to regenerate every managed
	// client secret via the admin API instead of just re-reading/re-writing the existing one.
	RotateSecrets bool

	// --- superadmin + seed ---

	// SuperadminUsername/Email are the one-time superadmin's Keycloak username/email.
	SuperadminUsername string
	SuperadminEmail    string
	// SuperadminPassword is the initial (forced-temporary) password, read by main.go from
	// KIBAN_SUPERADMIN_PASSWORD_FILE (never a plain env var: secrets are never stored in
	// env-visible places).
	SuperadminPassword string

	// RegistryPool connects to the registry service's OWN database as its OWN runtime role
	// (kiban_registry) — SeedStep calls registry.Store.Seed on this pool, the same rule.
	RegistryPool *pgxpool.Pool
	// AuthzPool connects to the authz service's OWN database as its OWN runtime role
	// (kiban_authz) — SeedStep seeds structural tuples via authz/store.Grant on this pool.
	AuthzPool *pgxpool.Pool
	// OrgPool connects to the org service's OWN database as its OWN runtime role (kiban_org) —
	// SeedStep's MemberMappedUserBackfill sub-step reads org.member JOIN
	// identity.user_read_v and writes authz.tuple/grant_ledger through it: kiban_org already has
	// SELECT on identity.user_read_v and USAGE+INSERT on the authz schema
	// (migrations/authz/0005) — no new cross-service grant needed, unlike RegistryPool (which is
	// deliberately NOT granted read access to identity's user rows).
	OrgPool *pgxpool.Pool
	// InstalledModulesCSV is KIBAN_INSTALLED_MODULES, parsed by SeedStep the same way
	// cmd/registry/main.go parses it.
	InstalledModulesCSV string
}

// Runner runs an ordered list of Steps against one Deps, stopping at the first Failed result —
// later steps generally depend on earlier ones having actually succeeded (seeding needs
// migrations applied, superadmin creation needs the realm reconciled). Steps after a failure
// are simply never attempted; nothing about them is reported.
type Runner struct {
	Steps []Step
}

// Run executes every step in order, logging each outcome as it completes, and returns every
// result produced (including the failing one, if any) plus a non-nil error wrapping the first
// failure.
func (r *Runner) Run(ctx context.Context, deps *Deps) ([]Result, error) {
	results := make([]Result, 0, len(r.Steps))
	for _, step := range r.Steps {
		outcome, detail, err := step.Run(ctx, deps)
		res := Result{Step: step.Name(), Outcome: outcome, Detail: detail, Err: err}
		results = append(results, res)

		if deps.Logger != nil {
			if err != nil {
				deps.Logger.Error("bootstrap: step failed", slog.String("step", res.Step), slog.String("detail", res.Detail), slog.Any("error", err))
			} else {
				deps.Logger.Info("bootstrap: step finished", slog.String("step", res.Step), slog.String("outcome", string(res.Outcome)), slog.String("detail", res.Detail))
			}
		}

		if outcome == OutcomeFailed {
			return results, fmt.Errorf("bootstrap: step %q failed: %w", step.Name(), err)
		}
	}
	return results, nil
}
