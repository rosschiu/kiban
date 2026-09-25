// SPDX-License-Identifier: Apache-2.0

// Package registry implements the registry service: module catalog / installation /
// dependency state, the capability API, tenant defaults, and seed-missing-only bootstrap
// seeding.
package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authzstore "github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

// ErrModuleNotFound means the module key has no platform.module_catalog row at all — distinct
// from the three capability codes, which apply to a module the catalog DOES know about.
var ErrModuleNotFound = errors.New("registry: module not found")

// Store is the registry service's data access layer: a pgx pool plus the sqlc-generated
// Queries built from it.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an already-connected pool (the caller owns its lifecycle: connect with the
// service's own kiban_registry credentials).
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool returns the underlying pool (used by http.go for the /ready liveness check).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (no runtime DDL, ever; migrations are applied out-of-band by `make
// migrate-registry`, as the kiban owner role). Returns a clear, actionable error instead of
// letting the first real query fail with an opaque "relation does not exist".
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_registry`).Scan(&version)
	if err != nil {
		return fmt.Errorf(
			"registry: migrations not applied (run `make migrate-registry` against this database first): %w",
			err,
		)
	}
	if version <= 0 {
		return errors.New("registry: migrations table present but at version 0 — run `make migrate-registry`")
	}
	return nil
}

// Capability is the canonical capability shape: { module, installed, enabled, dependencies[],
// missingDependencies[] }.
type Capability struct {
	Module              string   `json:"module"`
	Installed           bool     `json:"installed"`
	Enabled             bool     `json:"enabled"`
	Dependencies        []string `json:"dependencies"`
	MissingDependencies []string `json:"missingDependencies"`
}

// Capability computes the capability shape for moduleKey and the first capability error code
// that applies to it, checked in the canonical order — MODULE_NOT_INSTALLED, then
// MODULE_DISABLED, then MODULE_DEPENDENCY_MISSING — or "" when the module is fully ready.
// Dependency resolution is transitive and cycle-safe (ListTransitiveDependencyKeys's recursive
// CTE). Returns ErrModuleNotFound if moduleKey has no catalog entry at all.
func (s *Store) Capability(ctx context.Context, moduleKey string) (Capability, string, error) {
	q := New(s.pool)

	if _, err := q.GetModuleCatalogEntry(ctx, moduleKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Capability{}, "", ErrModuleNotFound
		}
		return Capability{}, "", fmt.Errorf("registry: lookup catalog entry: %w", err)
	}

	depKeys, err := q.ListTransitiveDependencyKeys(ctx, moduleKey)
	if err != nil {
		return Capability{}, "", fmt.Errorf("registry: resolve transitive dependencies: %w", err)
	}
	if depKeys == nil {
		depKeys = []string{}
	}

	allKeys := make([]string, 0, len(depKeys)+1)
	allKeys = append(allKeys, moduleKey)
	allKeys = append(allKeys, depKeys...)

	statusRows, err := q.ListInstallationStatusForKeys(ctx, allKeys)
	if err != nil {
		return Capability{}, "", fmt.Errorf("registry: load installation status: %w", err)
	}
	type status struct{ installed, enabled bool }
	statuses := make(map[string]status, len(statusRows))
	for _, r := range statusRows {
		statuses[r.ModuleKey] = status{installed: r.Installed, enabled: r.Enabled}
	}

	self := statuses[moduleKey]
	installed := self.installed
	// enabled is forced false when not installed.
	enabled := installed && self.enabled

	missing := make([]string, 0, len(depKeys))
	for _, dk := range depKeys {
		st := statuses[dk]
		if !(st.installed && st.enabled) {
			missing = append(missing, dk)
		}
	}

	result := Capability{
		Module:              moduleKey,
		Installed:           installed,
		Enabled:             enabled,
		Dependencies:        depKeys,
		MissingDependencies: missing,
	}

	switch {
	case !installed:
		return result, errenv.CodeModuleNotInstalled, nil
	case !enabled:
		return result, errenv.CodeModuleDisabled, nil
	case len(missing) > 0:
		return result, errenv.CodeModuleDependencyMissing, nil
	default:
		return result, "", nil
	}
}

// CatalogEntry is one row of the public catalog listing (GET /api/platform/catalog).
type CatalogEntry struct {
	ModuleKey       string `json:"moduleKey"`
	DisplayName     string `json:"displayName"`
	ScopeType       string `json:"scopeType"`
	Mandatory       bool   `json:"mandatory"`
	BasePath        string `json:"basePath"`
	HealthPath      string `json:"healthPath"`
	Port            int32  `json:"port"`
	LicenseClass    string `json:"licenseClass"`
	ManifestVersion string `json:"manifestVersion"`
	IsActive        bool   `json:"isActive"`
	Installed       bool   `json:"installed"`
	Enabled         bool   `json:"enabled"`
}

// Catalog lists every module the registry knows about, for the gateway/shell.
func (s *Store) Catalog(ctx context.Context) ([]CatalogEntry, error) {
	q := New(s.pool)
	rows, err := q.ListModuleCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: list catalog: %w", err)
	}
	out := make([]CatalogEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, CatalogEntry{
			ModuleKey:       r.ModuleKey,
			DisplayName:     r.DisplayName,
			ScopeType:       r.ScopeType,
			Mandatory:       r.Mandatory,
			BasePath:        r.BasePath,
			HealthPath:      r.HealthPath,
			Port:            r.Port,
			LicenseClass:    r.LicenseClass,
			ManifestVersion: r.ManifestVersion,
			IsActive:        r.IsActive,
			Installed:       r.Installed,
			Enabled:         r.Enabled,
		})
	}
	return out, nil
}

// ErrMandatoryModule is returned by SetEnabled when asked to disable a mandatory module.
var ErrMandatoryModule = errors.New("registry: mandatory module cannot be disabled")

// ErrModuleNotInstalled is returned by SetEnabled when asked to enable a module whose
// installation row has installed=false: nothing is written — no enabled flip, no fragment
// activation, no default grants, no audit row.
var ErrModuleNotInstalled = errors.New("registry: module not installed")

// SetEnabled installs is a transactional mutation: enable/disable a module, writing the audit
// event in the SAME transaction. Enabling a module that isn't installed is refused
// (ErrModuleNotInstalled); disabling one is a no-op state (enabled is already forced false);
// disabling a mandatory module is rejected.
// auditRecord is called with the open transaction so http.go's audit.Writer can be reused
// without this package importing internal/audit (keeps the dependency direction one way).
func (s *Store) SetEnabled(
	ctx context.Context,
	moduleKey string,
	enabled bool,
	auditRecord func(ctx context.Context, tx pgx.Tx) error,
) (PlatformModuleInstallation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PlatformModuleInstallation{}, fmt.Errorf("registry: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)

	if !enabled {
		catalogEntry, err := q.GetModuleCatalogEntry(ctx, moduleKey)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return PlatformModuleInstallation{}, ErrModuleNotFound
			}
			return PlatformModuleInstallation{}, fmt.Errorf("registry: lookup catalog entry: %w", err)
		}
		if catalogEntry.Mandatory {
			return PlatformModuleInstallation{}, ErrMandatoryModule
		}
	} else {
		// Read the installation row inside the tx before writing anything. A missing row is
		// still ErrModuleNotFound (SetModuleEnabled's ErrNoRows below); installed=false is refused.
		statuses, err := q.ListInstallationStatusForKeys(ctx, []string{moduleKey})
		if err != nil {
			return PlatformModuleInstallation{}, fmt.Errorf("registry: lookup installation: %w", err)
		}
		if len(statuses) == 1 && !statuses[0].Installed {
			return PlatformModuleInstallation{}, ErrModuleNotInstalled
		}
	}

	result, err := q.SetModuleEnabled(ctx, SetModuleEnabledParams{ModuleKey: moduleKey, Enabled: enabled})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PlatformModuleInstallation{}, ErrModuleNotFound
		}
		return PlatformModuleInstallation{}, fmt.Errorf("registry: set enabled: %w", err)
	}

	// Keep the module's authz.model_fragment row's active flag in lockstep
	// with its enabled state, in the SAME transaction — disable makes its fragment's checks
	// answer false (never an error), re-enable makes them effective again, and a module with no
	// fragment row is an untouched no-op.
	if err := setAuthzFragmentActive(ctx, tx, moduleKey, enabled); err != nil {
		return PlatformModuleInstallation{}, err
	}

	// A module going installed+enabled via the admin API gets the same default
	// module-access grant treatment as Seed's own boot-time pass — every currently active
	// company defaulted, default-ONCE, in this SAME transaction (atomic with the enable itself).
	// Disabling a module writes no new grants (existing ones are left exactly as they are — the
	// same "never a row delete" posture as installation rows, mirrored here for authz tuples).
	if enabled {
		companyIDs, err := activeCompanyIDs(ctx, tx)
		if err != nil {
			return PlatformModuleInstallation{}, fmt.Errorf("registry: set enabled: list active companies: %w", err)
		}
		for _, companyID := range companyIDs {
			if _, err := authzstore.EnsureDefaultGrant(ctx, tx, defaultGrantActor, "", companyID, moduleKey); err != nil {
				return PlatformModuleInstallation{}, fmt.Errorf("registry: set enabled: default module-access grant company %s: %w", companyID, err)
			}
		}
	}

	if auditRecord != nil {
		if err := auditRecord(ctx, tx); err != nil {
			return PlatformModuleInstallation{}, fmt.Errorf("registry: audit mutation: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return PlatformModuleInstallation{}, fmt.Errorf("registry: commit tx: %w", err)
	}
	return result, nil
}
