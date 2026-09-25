// SPDX-License-Identifier: Apache-2.0

// Package timesheet implements the timesheet module service: projects (module-owned master
// data), entries (draft-only mutation), versioned submissions with an approve/reject status
// machine, and per-company configuration — built solely against the platform's Go "SDK" packages
// (internal/errenv, internal/audit, internal/httpx, internal/obs, internal/config) plus HTTP
// calls to org's member-facts API and authz's effective-access/grants APIs — never by reaching
// into any foundation schema.
package timesheet

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/modulekit"
)

// Store is the timesheet service's data access layer: a pgx pool (connected as kiban_timesheet)
// plus the audit writer for "audit.timesheet__events". No sqlc codegen (same as notification's
// store.go) — every query is hand-written SQL against timesheet's own schema only.
type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

func NewStore(pool *pgxpool.Pool, auditWriter *audit.Writer) *Store {
	return &Store{pool: pool, audit: auditWriter}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (ARCH-004: no runtime DDL, ever) — same pattern as every other service's Store.
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_timesheet`).Scan(&version)
	if err != nil {
		return fmt.Errorf("timesheet: migrations not applied (run `make migrate-timesheet` against this database first): %w", err)
	}
	if version <= 0 {
		return errors.New("timesheet: migrations table present but at version 0 — run `make migrate-timesheet`")
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------------------------

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("timesheet: validation: field %s: %s", e.Field, e.Message)
}

var (
	ErrConflict               = errors.New("timesheet: conflict")
	ErrProjectNotFound        = errors.New("timesheet: project not found")
	ErrEntryNotFound          = errors.New("timesheet: entry not found")
	ErrSubmissionNotFound     = errors.New("timesheet: submission not found")
	ErrEntryNotDraft          = errors.New("timesheet: entry is not draft")
	ErrNoDraftEntries         = errors.New("timesheet: no draft entries for that week")
	ErrNoApproverAssigned     = errors.New("timesheet: caller has no assigned approver")
	ErrNotAssignedApprover    = errors.New("timesheet: caller is not the assigned approver")
	ErrSubmissionSuperseded   = errors.New("timesheet: submission has been superseded")
	ErrSubmissionNotSubmitted = errors.New("timesheet: submission is not in submitted status")
)

var projectCodePattern = regexp.MustCompile(`^[A-Z0-9_-]{1,20}$`)

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

// isoMonday truncates t (already UTC) to the Monday of its ISO week, at midnight UTC.
func isoMonday(t time.Time) time.Time {
	t = t.UTC()
	wd := int(t.Weekday())
	if wd == 0 { // Sunday -> 7
		wd = 7
	}
	monday := t.AddDate(0, 0, -(wd - 1))
	return time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, time.UTC)
}

// ---- configuration --------------------------------------------------------------------------

type Config struct {
	CompanyID                    uuid.UUID
	EnforceBillableWithinActual  bool
	AllowBillableAboveEightHours bool
	AllowedPreviousWeeks         int
	AllowedFutureWeeks           int
}

// defaultConfig is the default row returned when a company has never set one — a
// missing row is never an error, it just means "defaults apply" (read never fails for lack of a
// row a company hasn't configured yet).
func defaultConfig(companyID uuid.UUID) Config {
	return Config{
		CompanyID: companyID, EnforceBillableWithinActual: true, AllowBillableAboveEightHours: false,
		AllowedPreviousWeeks: 4, AllowedFutureWeeks: 1,
	}
}

func (s *Store) GetConfig(ctx context.Context, companyID uuid.UUID) (Config, error) {
	var c Config
	var pgID pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT company_id, enforce_billable_within_actual, allow_billable_above_eight_hours,
		       allowed_previous_weeks, allowed_future_weeks
		FROM timesheet.configuration WHERE company_id = $1`,
		pgFromUUID(companyID),
	).Scan(&pgID, &c.EnforceBillableWithinActual, &c.AllowBillableAboveEightHours, &c.AllowedPreviousWeeks, &c.AllowedFutureWeeks)
	if err != nil {
		return defaultConfig(companyID), nil //nolint:nilerr // missing row = defaults, not an error
	}
	c.CompanyID = uuidFromPg(pgID)
	return c, nil
}

func (s *Store) UpdateConfig(ctx context.Context, actor string, companyID uuid.UUID, c Config) (Config, error) {
	if c.AllowedPreviousWeeks < 0 {
		return Config{}, &ValidationError{Field: "allowedPreviousWeeks", Message: "must be >= 0"}
	}
	if c.AllowedFutureWeeks < 0 {
		return Config{}, &ValidationError{Field: "allowedFutureWeeks", Message: "must be >= 0"}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Config{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx, `
		INSERT INTO timesheet.configuration (company_id, enforce_billable_within_actual, allow_billable_above_eight_hours, allowed_previous_weeks, allowed_future_weeks, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (company_id) DO UPDATE SET
			enforce_billable_within_actual = EXCLUDED.enforce_billable_within_actual,
			allow_billable_above_eight_hours = EXCLUDED.allow_billable_above_eight_hours,
			allowed_previous_weeks = EXCLUDED.allowed_previous_weeks,
			allowed_future_weeks = EXCLUDED.allowed_future_weeks,
			updated_at = now()`,
		pgFromUUID(companyID), c.EnforceBillableWithinActual, c.AllowBillableAboveEightHours, c.AllowedPreviousWeeks, c.AllowedFutureWeeks,
	)
	if err != nil {
		return Config{}, fmt.Errorf("timesheet: update config: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.config.update", Subject: "company_module:" + companyID.String() + "/timesheet",
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return Config{}, fmt.Errorf("timesheet: audit config update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Config{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	c.CompanyID = companyID
	return c, nil
}

// ---- projects (module-owned master data, admin CRUD) ----------------------------------------

type Project struct {
	ID        uuid.UUID
	CompanyID uuid.UUID
	Code      string
	Name      string
	Status    string
	CreatedAt time.Time
}

func validateProject(code, name, status string) error {
	if !projectCodePattern.MatchString(code) {
		return &ValidationError{Field: "code", Message: "must match ^[A-Z0-9_-]{1,20}$"}
	}
	if len(name) < 1 || len(name) > 100 {
		return &ValidationError{Field: "name", Message: "must be 1..100 characters"}
	}
	if status != "" && status != "active" && status != "inactive" {
		return &ValidationError{Field: "status", Message: "must be active or inactive"}
	}
	return nil
}

func (s *Store) CreateProject(ctx context.Context, actor string, companyID uuid.UUID, code, name, status string) (Project, error) {
	if status == "" {
		status = "active"
	}
	if err := validateProject(code, name, status); err != nil {
		return Project{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Project{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var p Project
	var pgID, pgCompanyID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO timesheet.project (company_id, code, name, status)
		VALUES ($1, $2, $3, $4)
		RETURNING id, company_id, code, name, status, created_at`,
		pgFromUUID(companyID), code, name, status,
	).Scan(&pgID, &pgCompanyID, &p.Code, &p.Name, &p.Status, &p.CreatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Project{}, ErrConflict
		}
		return Project{}, fmt.Errorf("timesheet: create project: %w", err)
	}
	p.ID, p.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.project.create", Subject: "project:" + p.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "code": code},
	}); err != nil {
		return Project{}, fmt.Errorf("timesheet: audit project create: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Project{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	return p, nil
}

func (s *Store) UpdateProject(ctx context.Context, actor string, companyID, projectID uuid.UUID, code, name, status string) (Project, error) {
	if status == "" {
		status = "active"
	}
	if err := validateProject(code, name, status); err != nil {
		return Project{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Project{}, fmt.Errorf("timesheet: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var p Project
	var pgID, pgCompanyID pgtype.UUID
	err = tx.QueryRow(ctx, `
		UPDATE timesheet.project SET code = $3, name = $4, status = $5, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING id, company_id, code, name, status, created_at`,
		pgFromUUID(companyID), pgFromUUID(projectID), code, name, status,
	).Scan(&pgID, &pgCompanyID, &p.Code, &p.Name, &p.Status, &p.CreatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Project{}, ErrConflict
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return Project{}, ErrProjectNotFound
		}
		return Project{}, fmt.Errorf("timesheet: update project: %w", err)
	}
	p.ID, p.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "timesheet.project.update", Subject: "project:" + p.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "code": code},
	}); err != nil {
		return Project{}, fmt.Errorf("timesheet: audit project update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Project{}, fmt.Errorf("timesheet: commit: %w", err)
	}
	return p, nil
}

func (s *Store) ListProjects(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]Project, int, error) {
	page, pageSize = modulekit.ClampPage(page, pageSize)

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM timesheet.project WHERE company_id = $1`, pgFromUUID(companyID)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("timesheet: count projects: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, code, name, status, created_at
		FROM timesheet.project WHERE company_id = $1
		ORDER BY code ASC LIMIT $2 OFFSET $3`,
		pgFromUUID(companyID), pageSize, (page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("timesheet: list projects: %w", err)
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		var pgID, pgCompanyID pgtype.UUID
		if err := rows.Scan(&pgID, &pgCompanyID, &p.Code, &p.Name, &p.Status, &p.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("timesheet: scan project: %w", err)
		}
		p.ID, p.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func (s *Store) getProject(ctx context.Context, companyID, projectID uuid.UUID) (Project, error) {
	var p Project
	var pgID, pgCompanyID pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, company_id, code, name, status, created_at FROM timesheet.project
		WHERE company_id = $1 AND id = $2`,
		pgFromUUID(companyID), pgFromUUID(projectID),
	).Scan(&pgID, &pgCompanyID, &p.Code, &p.Name, &p.Status, &p.CreatedAt)
	if err != nil {
		return Project{}, ErrProjectNotFound
	}
	p.ID, p.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
	return p, nil
}
