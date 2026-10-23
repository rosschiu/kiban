// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Handover ends the position's current assignment and assigns memberID in one transaction, so
// no check between the two ever finds the position empty. It refuses an empty position (a
// ValidationError: use AssignNow), an inactive member and a member of another company; it is
// idempotent when memberID already holds the position (ended is nil, the current assignment
// is returned); and when expected names an assignment that is no longer the current one it
// answers PositionHeldError with the current holder, so two administrators cannot both think
// they handed the position over. Both audit events carry the same handoverId.
func (s *Store) Handover(ctx context.Context, actor string, positionID, memberID uuid.UUID, expected *uuid.UUID) (ended *Assignment, created Assignment, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, Assignment{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return nil, Assignment{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}
	q := New(s.pool).WithTx(tx)

	memberRow, err := q.GetMember(ctx, pgFromUUID(memberID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, Assignment{}, ErrMemberNotFound
		}
		return nil, Assignment{}, fmt.Errorf("org: get member: %w", err)
	}
	member := memberFromRow(memberRow)
	if !member.IsActive {
		return nil, Assignment{}, ErrMemberInactive
	}
	positionRow, err := q.GetPosition(ctx, pgFromUUID(positionID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, Assignment{}, ErrPositionNotFound
		}
		return nil, Assignment{}, fmt.Errorf("org: get position: %w", err)
	}
	if positionFromRow(positionRow).CompanyID != member.CompanyID {
		return nil, Assignment{}, ErrCrossCompanyAssignment
	}

	today, err := s.today(ctx, tx)
	if err != nil {
		return nil, Assignment{}, err
	}
	heldRow, err := q.GetAssignmentOnDate(ctx, GetAssignmentOnDateParams{PositionID: pgFromUUID(positionID), ValidFrom: pgDate(today)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Assignment{}, &ValidationError{Field: "positionId", Message: "position has no current holder; assign instead of handing over"}
	}
	if err != nil {
		return nil, Assignment{}, fmt.Errorf("org: current holder: %w", err)
	}
	held := assignmentFromRow(heldRow)
	if held.MemberID == memberID {
		return nil, held, nil
	}
	if expected != nil && *expected != held.ID {
		return nil, Assignment{}, &PositionHeldError{AssignmentID: held.ID, MemberID: held.MemberID}
	}

	handoverID := uuid.New().String()
	extra := map[string]any{"handoverId": handoverID}
	endedAsg, err := s.endAssignmentTx(ctx, tx, q, actor, held.ID, today, extra)
	if err != nil {
		return nil, Assignment{}, err
	}
	created, err = s.createAssignmentTx(ctx, tx, q, actor, positionID, memberID, today, extra)
	if err != nil {
		return nil, Assignment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, Assignment{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return &endedAsg, created, nil
}
