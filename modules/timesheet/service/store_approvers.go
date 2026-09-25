// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/modulekit"
)

// ---- approver assignment (read-side index only; the enforceable grant lives in authz's own
// tuple store, written via AuthzClient.GrantRelation BEFORE this method is called — never here) -

type ApproverAssignment struct {
	CompanyID        uuid.UUID
	MemberID         uuid.UUID
	ApproverMemberID uuid.UUID
	AssignedAt       time.Time
}

// RecordApproverAssignment upserts the local read-side index row. Callers (http.go) MUST have
// already granted the company_module#submitter (to memberID's kcSub) and company_module#approver
// (to approverMemberID's kcSub) tuples through authz's /internal/authz/grants before calling this
// — this method never itself decides authorization, it only records what was granted so the
// approvers-list API has something to page through (authz has no list-by-object-relation query).
func (s *Store) RecordApproverAssignment(ctx context.Context, actor string, companyID, memberID, approverMemberID uuid.UUID, memberKcSub, approverKcSub string) (ApproverAssignment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ApproverAssignment{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var a ApproverAssignment
	var pgCompanyID, pgMemberID, pgApproverID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO timesheet.approver_assignment (company_id, member_id, member_kc_sub, approver_member_id, approver_kc_sub, assigned_by_kc_sub, assigned_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now(), now())
		ON CONFLICT (company_id, member_id) DO UPDATE SET
			approver_member_id = EXCLUDED.approver_member_id, approver_kc_sub = EXCLUDED.approver_kc_sub,
			assigned_by_kc_sub = EXCLUDED.assigned_by_kc_sub, updated_at = now()
		RETURNING company_id, member_id, approver_member_id, assigned_at`,
		pgFromUUID(companyID), pgFromUUID(memberID), memberKcSub, pgFromUUID(approverMemberID), approverKcSub, actor,
	).Scan(&pgCompanyID, &pgMemberID, &pgApproverID, &a.AssignedAt)
	if err != nil {
		return ApproverAssignment{}, fmt.Errorf("timesheet: record approver assignment: %w", err)
	}
	a.CompanyID, a.MemberID, a.ApproverMemberID = uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgApproverID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.approver.assign", Subject: "company_module:" + companyID.String() + "/timesheet",
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String(), "approverMemberId": approverMemberID.String()},
	}); err != nil {
		return ApproverAssignment{}, fmt.Errorf("timesheet: audit approver assign: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ApproverAssignment{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	return a, nil
}

// AssignedApprover returns the current approver assignment for memberID, if any.
func (s *Store) AssignedApprover(ctx context.Context, companyID, memberID uuid.UUID) (approverMemberID uuid.UUID, approverKcSub string, ok bool, err error) {
	var pgApproverID pgtype.UUID
	err = s.pool.QueryRow(ctx, `
		SELECT approver_member_id, approver_kc_sub FROM timesheet.approver_assignment
		WHERE company_id = $1 AND member_id = $2`,
		pgFromUUID(companyID), pgFromUUID(memberID),
	).Scan(&pgApproverID, &approverKcSub)
	if err != nil {
		return uuid.UUID{}, "", false, nil //nolint:nilerr // no assignment yet is not an error
	}
	return uuidFromPg(pgApproverID), approverKcSub, true, nil
}

func (s *Store) ListApproverAssignments(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]ApproverAssignment, int, error) {
	page, pageSize = modulekit.ClampPage(page, pageSize)

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM timesheet.approver_assignment WHERE company_id = $1`, pgFromUUID(companyID)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("timesheet: count approver assignments: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT company_id, member_id, approver_member_id, assigned_at FROM timesheet.approver_assignment
		WHERE company_id = $1 ORDER BY assigned_at ASC LIMIT $2 OFFSET $3`,
		pgFromUUID(companyID), pageSize, (page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("timesheet: list approver assignments: %w", err)
	}
	defer rows.Close()

	var out []ApproverAssignment
	for rows.Next() {
		var a ApproverAssignment
		var pgCompanyID, pgMemberID, pgApproverID pgtype.UUID
		if err := rows.Scan(&pgCompanyID, &pgMemberID, &pgApproverID, &a.AssignedAt); err != nil {
			return nil, 0, fmt.Errorf("timesheet: scan approver assignment: %w", err)
		}
		a.CompanyID, a.MemberID, a.ApproverMemberID = uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgApproverID)
		out = append(out, a)
	}
	return out, total, rows.Err()
}
