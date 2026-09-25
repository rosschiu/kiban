// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/rosschiu/kiban/internal/audit"
)

// ---- entries (one per member/project/day, draft-only mutation) ------------------------------

type Entry struct {
	ID            uuid.UUID
	CompanyID     uuid.UUID
	MemberID      uuid.UUID
	ProjectID     uuid.UUID
	EntryDate     time.Time
	RealHours     float64
	BillableHours float64
	Status        string
}

// validateHours enforces the hours rules: 0-24 for both; billable<=real when
// enforce_billable_within_actual; billable<=8 unless allow_billable_above_eight_hours.
func validateHours(cfg Config, real, billable float64) error {
	if real < 0 || real > 24 {
		return &ValidationError{Field: "realHours", Message: "must be between 0 and 24"}
	}
	if billable < 0 || billable > 24 {
		return &ValidationError{Field: "billableHours", Message: "must be between 0 and 24"}
	}
	if cfg.EnforceBillableWithinActual && billable > real {
		return &ValidationError{Field: "billableHours", Message: "must be <= realHours"}
	}
	if !cfg.AllowBillableAboveEightHours && billable > 8 {
		return &ValidationError{Field: "billableHours", Message: "must be <= 8 (allowBillableAboveEightHours is disabled)"}
	}
	return nil
}

// validateWeekWindow enforces the editable range: weekStart's Monday must fall within
// [thisWeekMonday - allowedPreviousWeeks, thisWeekMonday + allowedFutureWeeks].
func validateWeekWindow(cfg Config, now, entryDate time.Time) error {
	thisWeek := isoMonday(now)
	entryWeek := isoMonday(entryDate)
	earliest := thisWeek.AddDate(0, 0, -7*cfg.AllowedPreviousWeeks)
	latest := thisWeek.AddDate(0, 0, 7*cfg.AllowedFutureWeeks)
	if entryWeek.Before(earliest) || entryWeek.After(latest) {
		return &ValidationError{Field: "entryDate", Message: "outside the editable window for this company's configuration"}
	}
	return nil
}

// UpsertEntry creates or updates the caller's own draft entry for (memberID, projectID,
// entryDate). Only draft entries may be mutated; attempting to edit a submitted/approved/
// rejected entry (rejected reverts to draft on RejectSubmission, so this only ever blocks
// submitted/approved) fails with ErrEntryNotDraft.
func (s *Store) UpsertEntry(ctx context.Context, actor string, companyID, memberID, projectID uuid.UUID, entryDate time.Time, real, billable float64) (Entry, error) {
	cfg, err := s.GetConfig(ctx, companyID)
	if err != nil {
		return Entry{}, err
	}
	if err := validateHours(cfg, real, billable); err != nil {
		return Entry{}, err
	}
	if err := validateWeekWindow(cfg, time.Now().UTC(), entryDate); err != nil {
		return Entry{}, err
	}
	if _, err := s.getProject(ctx, companyID, projectID); err != nil {
		return Entry{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var existingStatus string
	err = tx.QueryRow(ctx, `
		SELECT status FROM timesheet.entry
		WHERE company_id = $1 AND member_id = $2 AND project_id = $3 AND entry_date = $4
		FOR UPDATE`,
		pgFromUUID(companyID), pgFromUUID(memberID), pgFromUUID(projectID), entryDate,
	).Scan(&existingStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, fmt.Errorf("timesheet: lock entry: %w", err)
	}
	if err == nil && existingStatus != "draft" {
		return Entry{}, ErrEntryNotDraft
	}

	var e Entry
	var pgID, pgCompanyID, pgMemberID, pgProjectID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO timesheet.entry (company_id, member_id, project_id, entry_date, real_hours, billable_hours, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'draft')
		ON CONFLICT (company_id, member_id, project_id, entry_date) DO UPDATE SET
			real_hours = EXCLUDED.real_hours, billable_hours = EXCLUDED.billable_hours,
			status = 'draft', updated_at = now()
		RETURNING id, company_id, member_id, project_id, entry_date, real_hours, billable_hours, status`,
		pgFromUUID(companyID), pgFromUUID(memberID), pgFromUUID(projectID), entryDate, real, billable,
	).Scan(&pgID, &pgCompanyID, &pgMemberID, &pgProjectID, &e.EntryDate, &e.RealHours, &e.BillableHours, &e.Status)
	if err != nil {
		return Entry{}, fmt.Errorf("timesheet: upsert entry: %w", err)
	}
	e.ID, e.CompanyID, e.MemberID, e.ProjectID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgProjectID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.entry.upsert", Subject: "timesheet_entry:" + e.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String(), "projectId": projectID.String(), "entryDate": entryDate.Format("2006-01-02")},
	}); err != nil {
		return Entry{}, fmt.Errorf("timesheet: audit entry upsert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Entry{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	return e, nil
}

func (s *Store) DeleteEntry(ctx context.Context, actor string, companyID, memberID, entryID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var status string
	err = tx.QueryRow(ctx, `
		SELECT status FROM timesheet.entry WHERE id = $1 AND company_id = $2 AND member_id = $3 FOR UPDATE`,
		pgFromUUID(entryID), pgFromUUID(companyID), pgFromUUID(memberID),
	).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEntryNotFound
		}
		return fmt.Errorf("timesheet: lock entry: %w", err)
	}
	if status != "draft" {
		return ErrEntryNotDraft
	}
	if _, err := tx.Exec(ctx, `DELETE FROM timesheet.entry WHERE id = $1`, pgFromUUID(entryID)); err != nil {
		return fmt.Errorf("timesheet: delete entry: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.entry.delete", Subject: "timesheet_entry:" + entryID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String()},
	}); err != nil {
		return fmt.Errorf("timesheet: audit entry delete: %w", err)
	}
	return tx.Commit(ctx)
}

// ListEntriesForWeek returns memberID's entries whose entry_date falls in [weekStart,
// weekStart+6] (weekStart MUST already be an ISO Monday — callers validate that at the HTTP
// boundary, see http.go's parseWeekStart).
func (s *Store) ListEntriesForWeek(ctx context.Context, companyID, memberID uuid.UUID, weekStart time.Time) ([]Entry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, member_id, project_id, entry_date, real_hours, billable_hours, status
		FROM timesheet.entry
		WHERE company_id = $1 AND member_id = $2 AND entry_date >= $3 AND entry_date < $3 + 7
		ORDER BY entry_date ASC`,
		pgFromUUID(companyID), pgFromUUID(memberID), weekStart,
	)
	if err != nil {
		return nil, fmt.Errorf("timesheet: list entries for week: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var pgID, pgCompanyID, pgMemberID, pgProjectID pgtype.UUID
		if err := rows.Scan(&pgID, &pgCompanyID, &pgMemberID, &pgProjectID, &e.EntryDate, &e.RealHours, &e.BillableHours, &e.Status); err != nil {
			return nil, fmt.Errorf("timesheet: scan entry: %w", err)
		}
		e.ID, e.CompanyID, e.MemberID, e.ProjectID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgMemberID), uuidFromPg(pgProjectID)
		out = append(out, e)
	}
	return out, rows.Err()
}
