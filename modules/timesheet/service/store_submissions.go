// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/modulekit"
)

// ErrIdempotencyConflict: idempotency keys are payload-bound (same idempotency_key_hash approach
// as notification): the same Idempotency-Key was reused
// by the same company+member with a DIFFERENT weekStart — reject instead of silently replaying
// the first request's submission, which would mask exactly this class of client bug.
var ErrIdempotencyConflict = errors.New("timesheet: idempotency key reused with a different payload")

// submissionIdempotencyPayloadHash is the canonical payload the idempotency key binds to:
// companyID + memberID + weekStart, NUL-separated and sha256-hashed — same shape as
// notification's idempotencyPayloadHash (modules/notification/service/store.go).
func submissionIdempotencyPayloadHash(companyID, memberID uuid.UUID, weekStart time.Time) string {
	h := sha256.New()
	h.Write(companyID[:])
	h.Write([]byte{0})
	h.Write(memberID[:])
	h.Write([]byte{0})
	h.Write([]byte(weekStart.Format("2006-01-02")))
	return hex.EncodeToString(h.Sum(nil))
}

// ---- submissions: versioned status machine draft->submitted->approved|rejected, rejected->draft
// One transaction covers the whole status transition plus its audit row.

type Submission struct {
	ID                       uuid.UUID
	CompanyID                uuid.UUID
	MemberID                 uuid.UUID
	WeekStart                time.Time
	VersionNumber            int
	RootID                   uuid.UUID
	SupersedesID             *uuid.UUID
	IsCurrent                bool
	Status                   string
	AssignedApproverMemberID uuid.UUID
	AssignedApproverKcSub    string
	SubmittedByKcSub         string
	RejectReason             *string
}

// SubmitWeek is the submit transition (requires the company `submitter` relation AND an
// active member mapping — both checked by the CALLER, http.go, before this is invoked: the
// submitter relation via AuthzClient, the active member mapping via org's member-facts API).
// weekStart MUST already be an ISO Monday (validated at the HTTP boundary).
func (s *Store) SubmitWeek(ctx context.Context, actorKcSub string, companyID, memberID uuid.UUID, weekStart time.Time, idempotencyKey string) (Submission, bool, error) {
	if idempotencyKey != "" {
		if existing, existingHash, ok, err := s.findSubmissionByIdempotencyKey(ctx, companyID, memberID, idempotencyKey); err != nil {
			return Submission{}, false, err
		} else if ok {
			if existingHash != submissionIdempotencyPayloadHash(companyID, memberID, weekStart) {
				return Submission{}, false, ErrIdempotencyConflict
			}
			return existing, false, nil
		}
	}

	approverMemberID, approverKcSub, ok, err := s.AssignedApprover(ctx, companyID, memberID)
	if err != nil {
		return Submission{}, false, err
	}
	if !ok {
		return Submission{}, false, ErrNoApproverAssigned
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Submission{}, false, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rows, err := tx.Query(ctx, `
		SELECT e.id, e.project_id, p.code, p.name, e.entry_date, e.real_hours, e.billable_hours
		FROM timesheet.entry e JOIN timesheet.project p ON p.id = e.project_id
		WHERE e.company_id = $1 AND e.member_id = $2 AND e.entry_date >= $3 AND e.entry_date < $3 + 7
		  AND e.status = 'draft'
		FOR UPDATE OF e`,
		pgFromUUID(companyID), pgFromUUID(memberID), weekStart,
	)
	if err != nil {
		return Submission{}, false, fmt.Errorf("timesheet: lock draft entries: %w", err)
	}
	type draftEntry struct {
		id                       uuid.UUID
		projectID                uuid.UUID
		code, name               string
		entryDate                time.Time
		realHours, billableHours float64
	}
	var drafts []draftEntry
	for rows.Next() {
		var d draftEntry
		var pgID, pgProjectID pgtype.UUID
		if err := rows.Scan(&pgID, &pgProjectID, &d.code, &d.name, &d.entryDate, &d.realHours, &d.billableHours); err != nil {
			rows.Close()
			return Submission{}, false, fmt.Errorf("timesheet: scan draft entry: %w", err)
		}
		d.id, d.projectID = uuidFromPg(pgID), uuidFromPg(pgProjectID)
		drafts = append(drafts, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Submission{}, false, err
	}
	if len(drafts) == 0 {
		return Submission{}, false, ErrNoDraftEntries
	}

	// find + supersede the current version, if any (partial-unique is_current).
	var prevID uuid.UUID
	var prevVersion int
	var prevRootID uuid.UUID
	var hasPrev bool
	err = tx.QueryRow(ctx, `
		SELECT id, version_number, root_id FROM timesheet.submission
		WHERE company_id = $1 AND member_id = $2 AND week_start = $3 AND is_current
		FOR UPDATE`,
		pgFromUUID(companyID), pgFromUUID(memberID), weekStart,
	).Scan(&prevID, &prevVersion, &prevRootID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Submission{}, false, fmt.Errorf("timesheet: lock current submission: %w", err)
	}
	hasPrev = err == nil

	versionNumber := 1
	rootID := uuid.New()
	var supersedesID *uuid.UUID
	if hasPrev {
		versionNumber = prevVersion + 1
		rootID = prevRootID
		supersedesID = &prevID
		if _, err := tx.Exec(ctx, `UPDATE timesheet.submission SET is_current = false WHERE id = $1`, pgFromUUID(prevID)); err != nil {
			return Submission{}, false, fmt.Errorf("timesheet: supersede previous submission: %w", err)
		}
	}

	var sub Submission
	var pgID, pgCompanyID, pgMemberID, pgApproverID, pgRootIDIgnored, pgSupersedesIgnored pgtype.UUID
	var idemKey, idemHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		h := submissionIdempotencyPayloadHash(companyID, memberID, weekStart)
		idemHash = &h
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO timesheet.submission
			(company_id, member_id, week_start, version_number, root_id, supersedes_id, is_current, status,
			 assigned_approver_member_id, assigned_approver_kc_sub, submitted_by_kc_sub, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6, true, 'submitted', $7, $8, $9, $10, $11)
		RETURNING id, company_id, member_id, week_start, version_number, root_id, supersedes_id, is_current, status,
		          assigned_approver_member_id, assigned_approver_kc_sub, submitted_by_kc_sub`,
		pgFromUUID(companyID), pgFromUUID(memberID), weekStart, versionNumber, pgFromUUID(rootID), nullableUUID(supersedesID),
		pgFromUUID(approverMemberID), approverKcSub, actorKcSub, idemKey, idemHash,
	).Scan(&pgID, &pgCompanyID, &pgMemberID, &sub.WeekStart, &sub.VersionNumber, &pgRootIDIgnored, &pgSupersedesIgnored, &sub.IsCurrent, &sub.Status, &pgApproverID, &sub.AssignedApproverKcSub, &sub.SubmittedByKcSub)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Submission{}, false, ErrConflict
		}
		return Submission{}, false, fmt.Errorf("timesheet: insert submission: %w", err)
	}
	sub.ID, sub.CompanyID, sub.MemberID, sub.AssignedApproverMemberID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgApproverID)
	sub.RootID = rootID
	sub.SupersedesID = supersedesID

	for _, d := range drafts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO timesheet.submission_entry (submission_id, project_id, project_code, project_name, entry_date, real_hours, billable_hours)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			pgFromUUID(sub.ID), pgFromUUID(d.projectID), d.code, d.name, d.entryDate, d.realHours, d.billableHours,
		); err != nil {
			return Submission{}, false, fmt.Errorf("timesheet: insert submission entry snapshot: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE timesheet.entry SET status = 'submitted', updated_at = now() WHERE id = $1`, pgFromUUID(d.id)); err != nil {
			return Submission{}, false, fmt.Errorf("timesheet: mark entry submitted: %w", err)
		}
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actorKcSub, Action: "timesheet.submission.submit", Subject: "submission:" + sub.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String(), "weekStart": weekStart.Format("2006-01-02"), "versionNumber": versionNumber},
	}); err != nil {
		return Submission{}, false, fmt.Errorf("timesheet: audit submit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Submission{}, false, fmt.Errorf("timesheet: commit: %w", err)
	}
	return sub, true, nil
}

func nullableUUID(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return pgFromUUID(*id)
}

// findSubmissionByIdempotencyKey also returns the stored payload hash (empty string for a
// legacy row inserted before idempotency_key_hash existed) so SubmitWeek can distinguish a
// genuine replay from a payload conflict — same shape as notification's
// findByIdempotencyKey (modules/notification/service/store.go).
func (s *Store) findSubmissionByIdempotencyKey(ctx context.Context, companyID, memberID uuid.UUID, key string) (Submission, string, bool, error) {
	var sub Submission
	var pgID, pgCompanyID, pgMemberID, pgRootID, pgApproverID, pgSupersedes pgtype.UUID
	var reason *string
	var hash *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, company_id, member_id, week_start, version_number, root_id, supersedes_id, is_current, status,
		       assigned_approver_member_id, assigned_approver_kc_sub, submitted_by_kc_sub, reject_reason, idempotency_key_hash
		FROM timesheet.submission WHERE company_id = $1 AND member_id = $2 AND idempotency_key = $3`,
		pgFromUUID(companyID), pgFromUUID(memberID), key,
	).Scan(
		&pgID, &pgCompanyID, &pgMemberID, &sub.WeekStart, &sub.VersionNumber, &pgRootID, &pgSupersedes, &sub.IsCurrent, &sub.Status,
		&pgApproverID, &sub.AssignedApproverKcSub, &sub.SubmittedByKcSub, &reason, &hash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Submission{}, "", false, nil
		}
		return Submission{}, "", false, err
	}
	sub.ID, sub.CompanyID, sub.MemberID, sub.RootID, sub.AssignedApproverMemberID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgRootID), uuidFromPg(pgApproverID)
	if pgSupersedes.Valid {
		id := uuidFromPg(pgSupersedes)
		sub.SupersedesID = &id
	}
	sub.RejectReason = reason
	hashStr := ""
	if hash != nil {
		hashStr = *hash
	}
	return sub, hashStr, true, nil
}

func (s *Store) scanOneSubmission(ctx context.Context, query string, args ...any) (Submission, error) {
	var sub Submission
	var pgID, pgCompanyID, pgMemberID, pgRootID, pgApproverID pgtype.UUID
	var pgSupersedes pgtype.UUID
	var reason *string
	err := s.pool.QueryRow(ctx, query, args...).Scan(
		&pgID, &pgCompanyID, &pgMemberID, &sub.WeekStart, &sub.VersionNumber, &pgRootID, &pgSupersedes, &sub.IsCurrent, &sub.Status,
		&pgApproverID, &sub.AssignedApproverKcSub, &sub.SubmittedByKcSub, &reason,
	)
	if err != nil {
		return Submission{}, err
	}
	sub.ID, sub.CompanyID, sub.MemberID, sub.RootID, sub.AssignedApproverMemberID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgRootID), uuidFromPg(pgApproverID)
	if pgSupersedes.Valid {
		id := uuidFromPg(pgSupersedes)
		sub.SupersedesID = &id
	}
	sub.RejectReason = reason
	return sub, nil
}

func (s *Store) GetSubmission(ctx context.Context, companyID, submissionID uuid.UUID) (Submission, error) {
	sub, err := s.scanOneSubmission(ctx, `
		SELECT id, company_id, member_id, week_start, version_number, root_id, supersedes_id, is_current, status,
		       assigned_approver_member_id, assigned_approver_kc_sub, submitted_by_kc_sub, reject_reason
		FROM timesheet.submission WHERE company_id = $1 AND id = $2`,
		pgFromUUID(companyID), pgFromUUID(submissionID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Submission{}, ErrSubmissionNotFound
		}
		return Submission{}, fmt.Errorf("timesheet: get submission: %w", err)
	}
	return sub, nil
}

// decide is the shared approve/reject transition (assigned approver only; superseded
// (is_current=false) submissions can never be approved; reject requires a reason and reverts the
// submission's entries to draft; approve requires status=submitted and is_current=true).
func (s *Store) decideSubmission(ctx context.Context, actorKcSub string, companyID, submissionID uuid.UUID, approve bool, reason string) (Submission, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Submission{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var status string
	var isCurrent bool
	var assignedApproverKcSub string
	var weekStart time.Time
	var memberID uuid.UUID
	var pgMemberID pgtype.UUID
	err = tx.QueryRow(ctx, `
		SELECT status, is_current, assigned_approver_kc_sub, week_start, member_id
		FROM timesheet.submission WHERE company_id = $1 AND id = $2 FOR UPDATE`,
		pgFromUUID(companyID), pgFromUUID(submissionID),
	).Scan(&status, &isCurrent, &assignedApproverKcSub, &weekStart, &pgMemberID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Submission{}, ErrSubmissionNotFound
		}
		return Submission{}, fmt.Errorf("timesheet: lock submission: %w", err)
	}
	memberID = uuidFromPg(pgMemberID)

	if assignedApproverKcSub != actorKcSub {
		return Submission{}, ErrNotAssignedApprover
	}
	if !isCurrent {
		// "a superseded rejected version can never be approved" — applies to reject too:
		// a superseded version is no longer actionable at all, it's history.
		return Submission{}, ErrSubmissionSuperseded
	}
	if status != "submitted" {
		return Submission{}, ErrSubmissionNotSubmitted
	}

	newStatus := "rejected"
	action := "timesheet.submission.reject"
	if approve {
		newStatus = "approved"
		action = "timesheet.submission.approve"
	}

	var reasonArg any
	if !approve {
		if reason == "" {
			return Submission{}, &ValidationError{Field: "reason", Message: "required to reject"}
		}
		reasonArg = reason
	}

	if _, err := tx.Exec(ctx, `
		UPDATE timesheet.submission SET status = $3, decided_by_kc_sub = $4, decided_at = now(), reject_reason = $5
		WHERE id = $1 AND company_id = $2`,
		pgFromUUID(submissionID), pgFromUUID(companyID), newStatus, actorKcSub, reasonArg,
	); err != nil {
		return Submission{}, fmt.Errorf("timesheet: update submission status: %w", err)
	}

	entryStatus := "approved"
	if !approve {
		// rejected -> draft: entries become mutable again.
		entryStatus = "draft"
	}
	if _, err := tx.Exec(ctx, `
		UPDATE timesheet.entry SET status = $4, updated_at = now()
		WHERE company_id = $1 AND member_id = $2 AND entry_date >= $3 AND entry_date < $3 + 7 AND status = 'submitted'`,
		pgFromUUID(companyID), pgFromUUID(memberID), weekStart, entryStatus,
	); err != nil {
		return Submission{}, fmt.Errorf("timesheet: update entry status on decision: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actorKcSub, Action: action, Subject: "submission:" + submissionID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "reason": reason},
	}); err != nil {
		return Submission{}, fmt.Errorf("timesheet: audit decision: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Submission{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	return s.GetSubmission(ctx, companyID, submissionID)
}

func (s *Store) ApproveSubmission(ctx context.Context, actorKcSub string, companyID, submissionID uuid.UUID) (Submission, error) {
	return s.decideSubmission(ctx, actorKcSub, companyID, submissionID, true, "")
}

func (s *Store) RejectSubmission(ctx context.Context, actorKcSub string, companyID, submissionID uuid.UUID, reason string) (Submission, error) {
	return s.decideSubmission(ctx, actorKcSub, companyID, submissionID, false, reason)
}

// ListSubmissions supports view=mine|approvals|all (standard pagination shape).
func (s *Store) ListSubmissions(ctx context.Context, companyID uuid.UUID, scope, callerKcSub string, callerMemberID uuid.UUID, page, pageSize int) ([]Submission, int, error) {
	page, pageSize = modulekit.ClampPage(page, pageSize)

	var where string
	var args []any
	args = append(args, pgFromUUID(companyID))
	switch scope {
	case "approvals":
		where = "company_id = $1 AND assigned_approver_kc_sub = $2"
		args = append(args, callerKcSub)
	case "all":
		where = "company_id = $1"
	default: // "mine"
		where = "company_id = $1 AND member_id = $2"
		args = append(args, pgFromUUID(callerMemberID))
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM timesheet.submission WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("timesheet: count submissions: %w", err)
	}

	args = append(args, pageSize, (page-1)*pageSize)
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, member_id, week_start, version_number, root_id, supersedes_id, is_current, status,
		       assigned_approver_member_id, assigned_approver_kc_sub, submitted_by_kc_sub, reject_reason
		FROM timesheet.submission WHERE `+where+` ORDER BY submitted_at DESC `+limitOffset, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("timesheet: list submissions: %w", err)
	}
	defer rows.Close()

	var out []Submission
	for rows.Next() {
		var sub Submission
		var pgID, pgCompanyID, pgMemberID, pgRootID, pgApproverID, pgSupersedes pgtype.UUID
		var reason *string
		if err := rows.Scan(&pgID, &pgCompanyID, &pgMemberID, &sub.WeekStart, &sub.VersionNumber, &pgRootID, &pgSupersedes, &sub.IsCurrent, &sub.Status,
			&pgApproverID, &sub.AssignedApproverKcSub, &sub.SubmittedByKcSub, &reason); err != nil {
			return nil, 0, fmt.Errorf("timesheet: scan submission: %w", err)
		}
		sub.ID, sub.CompanyID, sub.MemberID, sub.RootID, sub.AssignedApproverMemberID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgRootID), uuidFromPg(pgApproverID)
		if pgSupersedes.Valid {
			id := uuidFromPg(pgSupersedes)
			sub.SupersedesID = &id
		}
		sub.RejectReason = reason
		out = append(out, sub)
	}
	return out, total, rows.Err()
}
