// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// DefaultGrantBackfill is the bootstrap converge step that writes the default module-access
// grant for every EXISTING (active company × installed+enabled module) pair, so stacks that
// predate default grants work without manual intervention. It reads active companies and
// installed+enabled modules through regPool (kiban_registry's own
// role — granted read access to org.org_unit/org_unit_type by migrations/org/0008 and already
// owning platform.module_installation outright), then writes each pair's default grant through
// authzPool via authz/store.EnsureDefaultGrant (default-ONCE, audited, never a raw INSERT).
// Safe to call on every bootstrap run: already-defaulted pairs (whether still granted or
// deliberately excluded since) are untouched.
func DefaultGrantBackfill(ctx context.Context, regPool, authzPool *pgxpool.Pool, actor string) (string, bool, error) {
	companyIDs, err := activeCompanyIDs(ctx, regPool)
	if err != nil {
		return "", false, fmt.Errorf("default grant backfill: list active companies: %w", err)
	}
	moduleKeys, err := enabledModuleKeys(ctx, regPool)
	if err != nil {
		return "", false, fmt.Errorf("default grant backfill: list enabled modules: %w", err)
	}

	considered := 0
	newlyGranted := 0
	for _, companyID := range companyIDs {
		for _, moduleKey := range moduleKeys {
			considered++
			applied, err := grantDefaultOnce(ctx, authzPool, actor, companyID, moduleKey)
			if err != nil {
				return "", false, fmt.Errorf("default grant backfill: company %s module %s: %w", companyID, moduleKey, err)
			}
			if applied {
				newlyGranted++
			}
		}
	}
	detail := fmt.Sprintf("default module-access grants: %d pair(s) considered (%d compan%s x %d module%s), %d newly granted",
		considered, len(companyIDs), plural(len(companyIDs), "y", "ies"), len(moduleKeys), plural(len(moduleKeys), "", "s"), newlyGranted)
	return detail, newlyGranted > 0, nil
}

func plural(n int, singular, pluralSuffix string) string {
	if n == 1 {
		return singular
	}
	return pluralSuffix
}

// activeCompanyIDs lists every org_unit whose type is org.org_unit_type.is_company = true and
// which is itself active — the "active company" half of the pair enumeration.
func activeCompanyIDs(ctx context.Context, regPool *pgxpool.Pool) ([]string, error) {
	rows, err := regPool.Query(ctx, `
		SELECT ou.id::text
		FROM org.org_unit ou
		JOIN org.org_unit_type ut ON ut.key = ou.type_key
		WHERE ut.is_company = true AND ou.is_active = true
		ORDER BY ou.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// enabledModuleKeys lists every module_key currently installed AND enabled — the "installed+
// enabled module" half of the pair enumeration.
func enabledModuleKeys(ctx context.Context, regPool *pgxpool.Pool) ([]string, error) {
	rows, err := regPool.Query(ctx, `
		SELECT module_key FROM platform.module_installation
		WHERE installed = true AND enabled = true
		ORDER BY module_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// grantDefaultOnce runs authz/store.EnsureDefaultGrant in its own small transaction on authzPool
// — one pair, one commit, matching the same per-tuple granularity SeedStructuralTuples already
// uses for the (much smaller) structural-tuple set.
func grantDefaultOnce(ctx context.Context, authzPool *pgxpool.Pool, actor, companyID, moduleKey string) (bool, error) {
	tx, err := authzPool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	applied, err := store.EnsureDefaultGrant(ctx, tx, actor, "bootstrap-default", companyID, moduleKey)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit tx: %w", err)
	}
	return applied, nil
}
