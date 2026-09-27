// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
)

// MemberMappedUserBackfill is the bootstrap converge step: idempotent backfill of
// `member:<memberId>#mapped_user @ user:<kcSub>` for every member ALREADY linked to a user
// before the tuple-maintenance code path existed (Store.LinkUser/UnlinkUser only maintain the
// tuple going forward, on new link/unlink calls). Runs entirely on orgPool (kiban_org's own
// role) — it already has SELECT on identity.user_read_v (identity's published read view) and
// USAGE+INSERT on the authz schema (migrations/authz/0005), so no new cross-service
// grant is needed and no separate AuthzPool transaction either. Safe to call on every bootstrap
// run: store.Grant's `INSERT ... ON CONFLICT DO NOTHING` makes an already-granted pair a no-op.
func MemberMappedUserBackfill(ctx context.Context, orgPool *pgxpool.Pool, actor string) (string, bool, error) {
	rows, err := orgPool.Query(ctx, `
		SELECT m.id::text, u.kc_sub
		FROM org.member m
		JOIN identity.user_read_v u ON u.id = m.user_id
		WHERE m.user_id IS NOT NULL
		ORDER BY m.id`)
	if err != nil {
		return "", false, fmt.Errorf("member mapped_user backfill: list linked members: %w", err)
	}
	type linkedMember struct{ memberID, kcSub string }
	var pairs []linkedMember
	for rows.Next() {
		var p linkedMember
		if err := rows.Scan(&p.memberID, &p.kcSub); err != nil {
			rows.Close()
			return "", false, fmt.Errorf("member mapped_user backfill: scan: %w", err)
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("member mapped_user backfill: iterate: %w", err)
	}

	applied := 0
	for _, p := range pairs {
		wasApplied, err := grantMemberMappedUserOnce(ctx, orgPool, actor, p.memberID, p.kcSub)
		if err != nil {
			return "", false, fmt.Errorf("member mapped_user backfill: member %s: %w", p.memberID, err)
		}
		if wasApplied {
			applied++
		}
	}
	detail := fmt.Sprintf("member mapped_user tuples: %d linked member(s) considered, %d newly granted", len(pairs), applied)
	return detail, applied > 0, nil
}

// grantMemberMappedUserOnce grants ONE member's mapped_user tuple in its own small transaction
// (same per-pair granularity DefaultGrantBackfill/grantDefaultOnce already use) — a pre-check
// under the SAME transaction as the grant avoids relying on store.Grant's natural-key ON CONFLICT
// alone to report "already existed" vs. "newly granted" (Grant itself is silent on that
// distinction; the pre-check makes this function's own accounting correct).
func grantMemberMappedUserOnce(ctx context.Context, orgPool *pgxpool.Pool, actor, memberID, kcSub string) (bool, error) {
	tx, err := orgPool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	var existed int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='member' AND object_id=$1 AND relation='mapped_user'
		  AND subject_type='user' AND subject_id=$2 AND subject_relation=''`,
		memberID, kcSub,
	).Scan(&existed); err != nil {
		return false, fmt.Errorf("precheck: %w", err)
	}
	if existed > 0 {
		return false, nil
	}

	if err := store.Grant(ctx, tx, actor, "bootstrap-mapped-user", store.Tuple{
		ObjectType: "member", ObjectID: memberID, Relation: "mapped_user",
		SubjectType: "user", SubjectID: kcSub,
	}); err != nil {
		return false, fmt.Errorf("grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}
