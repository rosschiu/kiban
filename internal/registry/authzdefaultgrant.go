// SPDX-License-Identifier: Apache-2.0

// Registry's own half of the default module-access grant writer — after a module
// becomes installed+enabled (Seed at boot, or SetEnabled via the admin API), every currently
// active company gets `company_module:<companyId>/<moduleKey>#system @ system:platform`
// defaulted, default-ONCE, through authz's own audited authz/store.EnsureDefaultGrant — never a
// raw INSERT into authz.tuple. Runs on registry's OWN pool/role (kiban_registry), which
// migrations/org/0008 and migrations/authz/0005 grant exactly the cross-schema read (org.org_unit/
// org_unit_type) and write (authz.tuple/grant_ledger/default_grant) access this needs.
package registry

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

const defaultGrantActor = "registry-default"

// txQueryer is the minimal read interface activeCompanyIDsTx needs — satisfied by pgx.Tx, so
// SetEnabled can list active companies INSIDE its own already-open transaction (atomic with the
// enable + default-grant writes it wraps), without this file depending on *pgxpool.Pool for that
// call site.
type txQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// activeCompanyIDs lists every ACTIVE company org_unit id (text form) — the same query
// internal/bootstrap's own backfill runs, duplicated here (not shared) because it is the one raw
// SQL statement this package needs and internal/bootstrap already depends on internal/registry
// (importing the other way would cycle). q is a pool (Seed) or SetEnabled's own transaction.
func activeCompanyIDs(ctx context.Context, q txQueryer) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT ou.id::text
		FROM org.org_unit ou
		JOIN org.org_unit_type ut ON ut.key = ou.type_key
		WHERE ut.is_company = true AND ou.is_active = true
		ORDER BY ou.id`)
	if err != nil {
		return nil, fmt.Errorf("registry: list active companies for default grant: %w", err)
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

// defaultGrantModuleForAllActiveCompanies grants moduleKey's default company_module tuple for
// every currently active company, one small transaction per company (default-ONCE means a
// re-run — e.g. Seed on every boot, or SetEnabled toggled off then on again — is always safe:
// already-defaulted pairs are untouched, whether still granted or since excluded).
func defaultGrantModuleForAllActiveCompanies(ctx context.Context, pool *pgxpool.Pool, moduleKey string) error {
	companyIDs, err := activeCompanyIDs(ctx, pool)
	if err != nil {
		return err
	}
	for _, companyID := range companyIDs {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("registry: default grant: begin tx: %w", err)
		}
		if _, err := store.EnsureDefaultGrant(ctx, tx, defaultGrantActor, "", companyID, moduleKey); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("registry: default grant company %s module %s: %w", companyID, moduleKey, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("registry: default grant: commit tx: %w", err)
		}
	}
	return nil
}
