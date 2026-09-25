// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// CompanyMemberBackfill is the bootstrap converge step: idempotent backfill of
// `company:<companyId>#member @ member:<memberId>#mapped_user` for every ACTIVE member that
// predates org.Store.CreateMember/UpdateMember maintaining the tuple. Same shape and
// pool as MemberMappedUserBackfill: runs entirely on orgPool (kiban_org has USAGE+INSERT on the
// authz schema — migrations/authz/0005), one small transaction per member, a same-transaction
// pre-check so the ledger gets exactly one grant row per tuple actually written and a converged
// re-run writes nothing.
func CompanyMemberBackfill(ctx context.Context, orgPool *pgxpool.Pool, actor string) (string, bool, error) {
	rows, err := orgPool.Query(ctx, `
		SELECT m.id::text, m.company_id::text
		FROM org.member m
		WHERE m.is_active = true
		ORDER BY m.id`)
	if err != nil {
		return "", false, fmt.Errorf("company member backfill: list active members: %w", err)
	}
	type activeMember struct{ memberID, companyID string }
	var pairs []activeMember
	for rows.Next() {
		var p activeMember
		if err := rows.Scan(&p.memberID, &p.companyID); err != nil {
			rows.Close()
			return "", false, fmt.Errorf("company member backfill: scan: %w", err)
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("company member backfill: iterate: %w", err)
	}

	applied := 0
	for _, p := range pairs {
		wasApplied, err := grantCompanyMemberOnce(ctx, orgPool, actor, p.companyID, p.memberID)
		if err != nil {
			return "", false, fmt.Errorf("company member backfill: member %s: %w", p.memberID, err)
		}
		if wasApplied {
			applied++
		}
	}
	detail := fmt.Sprintf("company member tuples: %d active member(s) considered, %d newly granted", len(pairs), applied)
	return detail, applied > 0, nil
}

func grantCompanyMemberOnce(ctx context.Context, orgPool *pgxpool.Pool, actor, companyID, memberID string) (bool, error) {
	tx, err := orgPool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	var existed int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company' AND object_id=$1 AND relation='member'
		  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
		companyID, memberID,
	).Scan(&existed); err != nil {
		return false, fmt.Errorf("precheck: %w", err)
	}
	if existed > 0 {
		return false, nil
	}

	if err := store.Grant(ctx, tx, actor, "bootstrap-company-member", store.Tuple{
		ObjectType: "company", ObjectID: companyID, Relation: "member",
		SubjectType: "member", SubjectID: memberID, SubjectRelation: "mapped_user",
	}); err != nil {
		return false, fmt.Errorf("grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}
