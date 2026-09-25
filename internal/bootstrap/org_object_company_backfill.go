// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// OrgObjectCompanyBackfill is the bootstrap converge step: idempotent backfill of
// `position:<id>#company @ company:<companyId>` and `group:<id>#company @ company:<companyId>`
// for every position and group that predates org.Store.CreatePosition/CreateGroup writing the
// anchor. Same shape and pool as CompanyMemberBackfill: runs entirely on
// orgPool, one small transaction per object, a same-transaction pre-check so the ledger gets
// exactly one grant row per tuple actually written and a converged re-run writes nothing.
func OrgObjectCompanyBackfill(ctx context.Context, orgPool *pgxpool.Pool, actor string) (string, bool, error) {
	rows, err := orgPool.Query(ctx, `
		SELECT 'position', id::text, company_id::text FROM org.position
		UNION ALL
		SELECT 'group', id::text, company_id::text FROM org."group"
		ORDER BY 1, 2`)
	if err != nil {
		return "", false, fmt.Errorf("org object company backfill: list positions/groups: %w", err)
	}
	type orgObject struct{ objType, id, companyID string }
	var objs []orgObject
	for rows.Next() {
		var o orgObject
		if err := rows.Scan(&o.objType, &o.id, &o.companyID); err != nil {
			rows.Close()
			return "", false, fmt.Errorf("org object company backfill: scan: %w", err)
		}
		objs = append(objs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("org object company backfill: iterate: %w", err)
	}

	applied := 0
	for _, o := range objs {
		wasApplied, err := grantOrgObjectCompanyOnce(ctx, orgPool, actor, o.objType, o.id, o.companyID)
		if err != nil {
			return "", false, fmt.Errorf("org object company backfill: %s %s: %w", o.objType, o.id, err)
		}
		if wasApplied {
			applied++
		}
	}
	detail := fmt.Sprintf("position/group company tuples: %d object(s) considered, %d newly granted", len(objs), applied)
	return detail, applied > 0, nil
}

func grantOrgObjectCompanyOnce(ctx context.Context, orgPool *pgxpool.Pool, actor, objType, id, companyID string) (bool, error) {
	tx, err := orgPool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	var existed int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type=$1 AND object_id=$2 AND relation='company'
		  AND subject_type='company' AND subject_id=$3 AND subject_relation=''`,
		objType, id, companyID,
	).Scan(&existed); err != nil {
		return false, fmt.Errorf("precheck: %w", err)
	}
	if existed > 0 {
		return false, nil
	}

	if err := store.Grant(ctx, tx, actor, "bootstrap-org-object-company", store.Tuple{
		ObjectType: objType, ObjectID: id, Relation: "company",
		SubjectType: "company", SubjectID: companyID,
	}); err != nil {
		return false, fmt.Errorf("grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}
