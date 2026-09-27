// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/registry"
)

// SystemPlatformID is the base authz model's one well-known `system` object id — model.json's
// `system#superadmin` relation ("this": true) is the platform-wide anchor every base type's
// `admin` union ultimately reaches via `tupleToUserset(system, superadmin)` (company, module,
// company_module, ...). There is exactly one platform, so exactly one `system` object; this
// constant IS the platform, not a per-tenant id. Owned by authz/store (the tuple's writer).
const SystemPlatformID = store.SystemPlatformID

// KnownModules is the built-in module manifest set SeedStep validates KIBAN_INSTALLED_MODULES
// against, mirroring cmd/registry/main.go's own `builtinModules` (currently empty — no module
// registration workflow exists yet, so a non-empty KIBAN_INSTALLED_MODULES today loudly fails,
// which is correct). Tests override this via Deps (see seed_test.go) to exercise the
// non-overwrite proof with a synthetic manifest without touching this production list.
var KnownModules = []registry.ModuleManifest{}

// StructuralTuples is the production set of structural authz tuples SeedStep grants on every
// run (idempotent by natural key). Currently empty: per-company structural parents
// (`company#admin`, `company_module#admin`, ...) are org's own runtime concern, not a platform
// one-shot bootstrap concern, and the superadmin's own `system:platform#superadmin` tuple is
// SuperadminStep's one-time write (and authz's grant/revoke routes' afterwards) — never a
// projection re-seeded here. The grant mechanism below (SeedStructuralTuples) is real,
// transactional, and tested (see seed_test.go's synthetic-tuple proof) — this var is simply
// empty until a feature needs a genuine structural fact seeded here.
var StructuralTuples []store.Tuple

// SeedStep seeds registry modules (seed-missing-only, never overwriting an existing row) via
// registry's own Seed package, then structural authz tuples via authz/store's transactional
// grant API with a post-write re-check. Both go through the owning service's imported Go code
// (authz/store is authz's OWN published transactional API for exactly this purpose, not a
// bypass of it).
type SeedStep struct{}

func (SeedStep) Name() string { return "seed" }

func (SeedStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	var details []string
	applied := false

	if deps.RegistryPool != nil {
		regStore := registry.NewStore(deps.RegistryPool)
		installed, err := registry.ParseInstalledModules(deps.InstalledModulesCSV, KnownModules)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: parse KIBAN_INSTALLED_MODULES: %w", err)
		}

		installationRowsBefore, err := countModuleInstallationRows(ctx, deps.RegistryPool, KnownModules)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: count installation rows before: %w", err)
		}
		if err := regStore.Seed(ctx, KnownModules, installed); err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: registry modules: %w", err)
		}
		installationRowsAfter, err := countModuleInstallationRows(ctx, deps.RegistryPool, KnownModules)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: count installation rows after: %w", err)
		}

		regApplied := installationRowsAfter > installationRowsBefore
		applied = applied || regApplied
		details = append(details, fmt.Sprintf("registry: seeded (%d known modules, %s)", len(KnownModules), outcomeWord(regApplied)))
	} else {
		details = append(details, "registry: skipped (RegistryPool not set)")
	}

	if deps.AuthzPool != nil {
		tupleDetail, tupleApplied, err := SeedStructuralTuples(ctx, deps.AuthzPool, "bootstrap", StructuralTuples)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: structural tuples: %w", err)
		}
		applied = applied || tupleApplied
		details = append(details, tupleDetail)

		// Default-grant backfill — every (active company × installed+enabled module) pair gets
		// `company_module:<companyId>/<moduleKey>#system @ system:platform` written ONCE (the
		// per-company half of the superadmin resolution chain). Reads go through deps.RegistryPool
		// (kiban_registry's own role, granted read access to org.org_unit/org_unit_type by
		// migrations/org/0008 specifically for this purpose — no separate OrgPool needed);
		// writes go through deps.AuthzPool via authz/store.EnsureDefaultGrant, default-ONCE.
		if deps.RegistryPool != nil {
			grantDetail, grantApplied, err := DefaultGrantBackfill(ctx, deps.RegistryPool, deps.AuthzPool, "bootstrap-default")
			if err != nil {
				return OutcomeFailed, "", fmt.Errorf("seed: default module-access grants: %w", err)
			}
			applied = applied || grantApplied
			details = append(details, grantDetail)
		} else {
			details = append(details, "default module-access grants: skipped (RegistryPool not set)")
		}
	} else {
		details = append(details, "authz tuples: skipped (AuthzPool not set)")
	}

	// Member mapped_user backfill — every member ALREADY linked to a user (before
	// LinkUser/UnlinkUser started maintaining the tuple on new link/unlink calls) gets
	// `member:<memberId>#mapped_user @ user:<kcSub>` granted, idempotently. Runs entirely on
	// OrgPool (see MemberMappedUserBackfill's own doc comment) — independent of AuthzPool/
	// RegistryPool being set.
	if deps.OrgPool != nil {
		mmDetail, mmApplied, err := MemberMappedUserBackfill(ctx, deps.OrgPool, "bootstrap-default")
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: member mapped_user backfill: %w", err)
		}
		applied = applied || mmApplied
		details = append(details, mmDetail)

		// Company member backfill — every ACTIVE member gets `company:<companyId>#member @
		// member:<memberId>#mapped_user` granted, idempotently (same pool, same shape).
		cmDetail, cmApplied, err := CompanyMemberBackfill(ctx, deps.OrgPool, "bootstrap-default")
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: company member backfill: %w", err)
		}
		applied = applied || cmApplied
		details = append(details, cmDetail)

		// Position/group company anchors — every position and group gets
		// `<type>:<id>#company @ company:<companyId>` granted, idempotently.
		ocDetail, ocApplied, err := OrgObjectCompanyBackfill(ctx, deps.OrgPool, "bootstrap-default")
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("seed: org object company backfill: %w", err)
		}
		applied = applied || ocApplied
		details = append(details, ocDetail)
	} else {
		details = append(details, "member mapped_user tuples: skipped (OrgPool not set)")
		details = append(details, "company member tuples: skipped (OrgPool not set)")
		details = append(details, "position/group company tuples: skipped (OrgPool not set)")
	}

	if applied {
		return OutcomeApplied, joinDetails(details), nil
	}
	return OutcomeConverged, joinDetails(details), nil
}

// countModuleInstallationRows counts how many of known's module keys already have a
// platform.module_installation row — used to distinguish OutcomeApplied (a new row was
// seed-created) from OutcomeConverged (every row already existed) around registry.Store.Seed,
// which itself doesn't report that distinction.
func countModuleInstallationRows(ctx context.Context, pool *pgxpool.Pool, known []registry.ModuleManifest) (int, error) {
	if len(known) == 0 {
		return 0, nil
	}
	keys := make([]string, len(known))
	for i, m := range known {
		keys[i] = m.ModuleKey
	}
	var count int
	err := pool.QueryRow(ctx, `SELECT count(*) FROM platform.module_installation WHERE module_key = ANY($1)`, keys).Scan(&count)
	return count, err
}

func joinDetails(details []string) string {
	out := ""
	for i, d := range details {
		if i > 0 {
			out += "; "
		}
		out += d
	}
	return out
}

// SeedStructuralTuples grants tuples via authz/store.Grant (one transaction), then re-checks
// each tuple's natural key is actually present (post-write re-check) —
// fail-closed: a grant that doesn't read back is a hard failure, never silently ignored.
// Idempotent by natural key: store.Grant's INSERT ... ON CONFLICT DO NOTHING means re-running
// with the same tuples is always OutcomeConverged (applied=false) after the first run.
func SeedStructuralTuples(ctx context.Context, pool *pgxpool.Pool, actor string, tuples []store.Tuple) (string, bool, error) {
	if len(tuples) == 0 {
		return "authz tuples: none configured (converged)", false, nil
	}

	if allTuplesExist, err := tuplesExist(ctx, pool, tuples); err != nil {
		return "", false, fmt.Errorf("pre-check existing tuples: %w", err)
	} else if allTuplesExist {
		return fmt.Sprintf("authz tuples: all %d already granted (converged)", len(tuples)), false, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if err := store.Grant(ctx, tx, actor, "bootstrap-seed", tuples...); err != nil {
		return "", false, fmt.Errorf("grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, fmt.Errorf("commit: %w", err)
	}

	// Post-write re-check, OUTSIDE the committing transaction (proves the COMMITTED state, not
	// just what the transaction believed it wrote) — fail-closed: a tuple that doesn't read
	// back is a hard failure.
	for _, tp := range tuples {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type=$1 AND object_id=$2 AND relation=$3
			  AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`,
			tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
		).Scan(&count)
		if err != nil {
			return "", false, fmt.Errorf("post-write re-check %+v: %w", tp, err)
		}
		if count == 0 {
			return "", false, fmt.Errorf("post-write re-check FAILED: tuple %+v not found after commit", tp)
		}
	}
	return fmt.Sprintf("authz tuples: granted %d, post-write re-check OK", len(tuples)), true, nil
}

func tuplesExist(ctx context.Context, pool *pgxpool.Pool, tuples []store.Tuple) (bool, error) {
	for _, tp := range tuples {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type=$1 AND object_id=$2 AND relation=$3
			  AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`,
			tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
		).Scan(&count)
		if err != nil {
			return false, err
		}
		if count == 0 {
			return false, nil
		}
	}
	return true, nil
}
