// SPDX-License-Identifier: Apache-2.0

// Store is the helpdesk service's data access layer: a pgx pool (connected as kiban_helpdesk,
// the module's own DB role) plus the audit writer for "audit.helpdesk__events". Hand-written SQL against
// helpdesk's own schema only — no sqlc codegen, same accepted v1 pattern notification's/
// timesheet's/docs's own Store use.
//
// AUTHORIZATION TIER CHECKS NEVER LIVE HERE — that is AuthzClient's job (http.go calls it before
// or alongside these methods). What DOES live here, deliberately, is per-ticket VISIBILITY and
// TRANSITION eligibility as plain row comparisons (reporter_kcsub/assignee_kcsub against the
// caller): visibility is enforced in service logic from those tiers. This module declares no object type and writes no per-ticket tuples, so
// there is no engine call to make for an individual ticket.
package helpdesk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/pgconv"
	"github.com/rosschiu/kiban/modulekit"
)

// ErrIdempotencyConflict means the same Idempotency-Key was reused with a DIFFERENT payload
// (same idempotency_key_hash approach as notification's) — reject instead of silently replaying the first request's result.
var ErrIdempotencyConflict = errors.New("helpdesk: idempotency key reused with a different payload")

// ticketIdempotencyPayloadHash is the canonical payload helpdesk.ticket's idempotency key binds
// to: companyID + reporterKcSub + title + description, NUL-separated and sha256-hashed.
func ticketIdempotencyPayloadHash(companyID uuid.UUID, reporterKcSub, title, description string) string {
	h := sha256.New()
	h.Write(companyID[:])
	h.Write([]byte{0})
	h.Write([]byte(reporterKcSub))
	h.Write([]byte{0})
	h.Write([]byte(title))
	h.Write([]byte{0})
	h.Write([]byte(description))
	return hex.EncodeToString(h.Sum(nil))
}

// commentIdempotencyPayloadHash is the canonical payload helpdesk.comment's idempotency key
// binds to: ticketID + authorKcSub + body, NUL-separated and sha256-hashed.
func commentIdempotencyPayloadHash(ticketID uuid.UUID, authorKcSub, body string) string {
	h := sha256.New()
	h.Write(ticketID[:])
	h.Write([]byte{0})
	h.Write([]byte(authorKcSub))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

func NewStore(pool *pgxpool.Pool, auditWriter *audit.Writer) *Store {
	return &Store{pool: pool, audit: auditWriter}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (ARCH-004: no runtime DDL, ever).
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_helpdesk`).Scan(&version)
	if err != nil {
		return fmt.Errorf("helpdesk: migrations not applied (run `make migrate-helpdesk` against this database first): %w", err)
	}
	if version <= 0 {
		return errors.New("helpdesk: migrations table present but at version 0 — run `make migrate-helpdesk`")
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------------------------

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("helpdesk: validation: field %s: %s", e.Field, e.Message)
}

var (
	ErrTicketNotFound = errors.New("helpdesk: ticket not found")
	ErrAgentNotFound  = errors.New("helpdesk: agent not found")
)

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

// ---- tickets ----------------------------------------------------------------------------------

const (
	StatusOpen       = "open"
	StatusInProgress = "in_progress"
	StatusResolved   = "resolved"
	StatusClosed     = "closed"
)

type Ticket struct {
	ID               uuid.UUID
	CompanyID        uuid.UUID
	Title            string
	Description      string
	Status           string
	ReporterMemberID uuid.UUID
	ReporterKcSub    string
	AssigneeMemberID *uuid.UUID
	AssigneeKcSub    *string
	// The OTHER assignee shape — a POSITION, never a snapshotted person. Exactly one
	// of AssigneeMemberID/AssigneePositionID is set at a time (migration 0005's CHECK). Who
	// CURRENTLY holds the position is never stored here — resolved at read time via authz's
	// object-mode `can` (AuthzClient.IsPositionHolder) — AssigneePositionTitle is a display-only
	// snapshot, exactly like helpdesk.agent.position_title, never used for any decision.
	AssigneePositionID    *uuid.UUID
	AssigneePositionTitle string
	// The THIRD assignee shape — a GROUP. "the current MEMBERS of this group work this
	// ticket" (plural, unlike position's single holder) — resolved at read time via authz's
	// object-mode `can` (AuthzClient.IsGroupMember), never snapshotted. AssigneeGroupTitle is a
	// display-only snapshot, same posture as AssigneePositionTitle.
	AssigneeGroupID    *uuid.UUID
	AssigneeGroupTitle string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// AssigneeKind reports which of the three assignee shapes this ticket carries: "member",
// "position", "group", or "" (unassigned).
func (t Ticket) AssigneeKind() string {
	switch {
	case t.AssigneePositionID != nil:
		return "position"
	case t.AssigneeGroupID != nil:
		return "group"
	case t.AssigneeMemberID != nil:
		return "member"
	default:
		return ""
	}
}

func validTitle(title string) error {
	if len(title) < 1 || len(title) > 200 {
		return &ValidationError{Field: "title", Message: "must be 1..200 characters"}
	}
	return nil
}

const ticketColumns = `id, company_id, title, description, status, reporter_member_id, reporter_kcsub, assignee_member_id, assignee_kcsub, assignee_position_id, assignee_position_title, assignee_group_id, assignee_group_title, created_at, updated_at`

// scanTicket scans ticketColumns; extra receives any trailing columns the caller SELECTed
// after them (FindTicketByIdempotencyKey appends idempotency_key_hash).
func scanTicket(row pgx.Row, extra ...any) (Ticket, error) {
	var t Ticket
	var pgID, pgCompanyID, pgReporterMemberID, pgAssigneeMemberID, pgAssigneePositionID, pgAssigneeGroupID pgtype.UUID
	var assigneeKcSub, assigneePositionTitle, assigneeGroupTitle pgtype.Text
	dest := append([]any{&pgID, &pgCompanyID, &t.Title, &t.Description, &t.Status, &pgReporterMemberID, &t.ReporterKcSub, &pgAssigneeMemberID, &assigneeKcSub, &pgAssigneePositionID, &assigneePositionTitle, &pgAssigneeGroupID, &assigneeGroupTitle, &t.CreatedAt, &t.UpdatedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return Ticket{}, err
	}
	t.ID, t.CompanyID, t.ReporterMemberID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgReporterMemberID)
	t.AssigneeMemberID = pgconv.UUIDPtrFromPg(pgAssigneeMemberID)
	if assigneeKcSub.Valid {
		t.AssigneeKcSub = &assigneeKcSub.String
	}
	t.AssigneePositionID = pgconv.UUIDPtrFromPg(pgAssigneePositionID)
	if assigneePositionTitle.Valid {
		t.AssigneePositionTitle = assigneePositionTitle.String
	}
	t.AssigneeGroupID = pgconv.UUIDPtrFromPg(pgAssigneeGroupID)
	if assigneeGroupTitle.Valid {
		t.AssigneeGroupTitle = assigneeGroupTitle.String
	}
	return t, nil
}

// FindTicketByIdempotencyKey looks up a previously created ticket by (companyID,
// reporterKcSub, idempotencyKey) — the handler calls this BEFORE creating a new ticket, so a
// replayed create-ticket request never creates a second row. Returns the stored payload hash
// (empty string for a row stored without a hash) alongside the ticket.
func (s *Store) FindTicketByIdempotencyKey(ctx context.Context, companyID uuid.UUID, reporterKcSub, idempotencyKey string) (Ticket, string, bool, error) {
	var hash *string
	row := s.pool.QueryRow(ctx, `
		SELECT `+ticketColumns+`, idempotency_key_hash
		FROM helpdesk.ticket WHERE company_id = $1 AND reporter_kcsub = $2 AND idempotency_key = $3`,
		pgFromUUID(companyID), reporterKcSub, idempotencyKey,
	)
	t, err := scanTicket(row, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Ticket{}, "", false, nil
		}
		return Ticket{}, "", false, fmt.Errorf("helpdesk: find ticket by idempotency key: %w", err)
	}
	hashStr := ""
	if hash != nil {
		hashStr = *hash
	}
	return t, hashStr, true, nil
}

// CreateTicket persists a new ticket — the reporter is always the caller (actor), never an
// arbitrary caller-supplied subject. idempotencyKey (may be "") is persisted alongside its payload
// hash for future replay detection via FindTicketByIdempotencyKey — this method itself does not
// replay/conflict-check (the handler already did).
func (s *Store) CreateTicket(ctx context.Context, actor string, companyID, reporterMemberID uuid.UUID, reporterKcSub, title, description, idempotencyKey string) (Ticket, error) {
	if err := validTitle(title); err != nil {
		return Ticket{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var idemKey, idemHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		h := ticketIdempotencyPayloadHash(companyID, reporterKcSub, title, description)
		idemHash = &h
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO helpdesk.ticket (company_id, title, description, status, reporter_member_id, reporter_kcsub, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, 'open', $4, $5, $6, $7)
		RETURNING `+ticketColumns,
		pgFromUUID(companyID), title, description, pgFromUUID(reporterMemberID), reporterKcSub, idemKey, idemHash,
	)
	t, err := scanTicket(row)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Ticket{}, ErrIdempotencyConflict
		}
		return Ticket{}, fmt.Errorf("helpdesk: create ticket: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.ticket.create", Subject: "helpdesk_ticket:" + t.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "title": title},
	}); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: audit ticket create: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return t, nil
}

func (s *Store) GetTicket(ctx context.Context, companyID, ticketID uuid.UUID) (Ticket, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+ticketColumns+` FROM helpdesk.ticket WHERE company_id = $1 AND id = $2`, pgFromUUID(companyID), pgFromUUID(ticketID))
	t, err := scanTicket(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ticket{}, ErrTicketNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: get ticket: %w", err)
	}
	return t, nil
}

// ListTickets returns tickets in companyID, optionally filtered by reporterKcSub (view=mine,
// pass a non-empty value) and/or status (pass "" for no filter).
func (s *Store) ListTickets(ctx context.Context, companyID uuid.UUID, reporterKcSub, status string) ([]Ticket, error) {
	query := `SELECT ` + ticketColumns + ` FROM helpdesk.ticket WHERE company_id = $1`
	args := []any{pgFromUUID(companyID)}
	if reporterKcSub != "" {
		args = append(args, reporterKcSub)
		query += fmt.Sprintf(" AND reporter_kcsub = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("helpdesk: list tickets: %w", err)
	}
	defer rows.Close()
	var out []Ticket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, fmt.Errorf("helpdesk: scan ticket: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AssignTicket sets the ticket's assignee to a MEMBER — clears any prior position assignment
// (exactly-one-of). Caller (http.go) MUST already have ensured the assignee holds the agent tier
// (granting it first via AuthzClient.GrantAgent + RecordAgent if they didn't) BEFORE calling
// this, mirroring docs's/timesheet's own "authorize, then persist" ordering.
func (s *Store) AssignTicket(ctx context.Context, actor string, companyID, ticketID, assigneeMemberID uuid.UUID, assigneeKcSub string) (Ticket, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		UPDATE helpdesk.ticket
		SET assignee_member_id = $3, assignee_kcsub = $4,
		    assignee_position_id = NULL, assignee_position_title = NULL,
		    assignee_group_id = NULL, assignee_group_title = NULL, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING `+ticketColumns,
		pgFromUUID(companyID), pgFromUUID(ticketID), pgFromUUID(assigneeMemberID), assigneeKcSub,
	)
	t, err := scanTicket(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ticket{}, ErrTicketNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: assign ticket: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.ticket.assign", Subject: "helpdesk_ticket:" + t.ID.String(),
		Payload: map[string]any{"assigneeMemberId": assigneeMemberID.String()},
	}); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: audit ticket assign: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return t, nil
}

// AssignTicketToPosition sets the ticket's assignee to a POSITION — clears any prior member
// assignment (exactly-one-of). positionTitle is a display-only snapshot (never used for any
// decision — see the Ticket.AssigneePositionTitle doc comment); the resolve-at-read holder
// lookup is entirely AuthzClient/OrgClient's job at read/notify time, never this store's.
// Caller (http.go) MUST already have verified the position is bound as a helpdesk agent (else
// 422 "position is not a helpdesk agent binding") BEFORE calling this.
func (s *Store) AssignTicketToPosition(ctx context.Context, actor string, companyID, ticketID, positionID uuid.UUID, positionTitle string) (Ticket, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		UPDATE helpdesk.ticket
		SET assignee_position_id = $3, assignee_position_title = $4,
		    assignee_member_id = NULL, assignee_kcsub = NULL,
		    assignee_group_id = NULL, assignee_group_title = NULL, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING `+ticketColumns,
		pgFromUUID(companyID), pgFromUUID(ticketID), pgFromUUID(positionID), positionTitle,
	)
	t, err := scanTicket(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ticket{}, ErrTicketNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: assign ticket to position: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.ticket.assign", Subject: "helpdesk_ticket:" + t.ID.String(),
		Payload: map[string]any{"assigneePositionId": positionID.String(), "positionTitle": positionTitle},
	}); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: audit ticket assign to position: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return t, nil
}

// AssignTicketToGroup sets the ticket's assignee to a GROUP — clears any prior member/position
// assignment (at-most-one-of). groupTitle is a display-only snapshot (never used for any
// decision — see the Ticket.AssigneeGroupTitle doc comment); the resolve-at-read member-fan-out
// is entirely AuthzClient/OrgClient's job at read/notify time, never this store's. Caller
// (http.go) MUST already have verified the group is bound as a helpdesk agent (else 422 "group
// is not a helpdesk agent binding") BEFORE calling this.
func (s *Store) AssignTicketToGroup(ctx context.Context, actor string, companyID, ticketID, groupID uuid.UUID, groupTitle string) (Ticket, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		UPDATE helpdesk.ticket
		SET assignee_group_id = $3, assignee_group_title = $4,
		    assignee_member_id = NULL, assignee_kcsub = NULL,
		    assignee_position_id = NULL, assignee_position_title = NULL, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING `+ticketColumns,
		pgFromUUID(companyID), pgFromUUID(ticketID), pgFromUUID(groupID), groupTitle,
	)
	t, err := scanTicket(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ticket{}, ErrTicketNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: assign ticket to group: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.ticket.assign", Subject: "helpdesk_ticket:" + t.ID.String(),
		Payload: map[string]any{"assigneeGroupId": groupID.String(), "groupTitle": groupTitle},
	}); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: audit ticket assign to group: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return t, nil
}

// UpdateTicketStatus moves a ticket to newStatus. Caller (http.go) MUST already have validated
// the transition is a legal edge and that the caller is entitled to trigger it.
func (s *Store) UpdateTicketStatus(ctx context.Context, actor string, companyID, ticketID uuid.UUID, fromStatus, newStatus string) (Ticket, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		UPDATE helpdesk.ticket SET status = $3, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING `+ticketColumns,
		pgFromUUID(companyID), pgFromUUID(ticketID), newStatus,
	)
	t, err := scanTicket(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ticket{}, ErrTicketNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: update ticket status: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.ticket.status", Subject: "helpdesk_ticket:" + t.ID.String(),
		Payload: map[string]any{"from": fromStatus, "to": newStatus},
	}); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: audit ticket status: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return t, nil
}

// CountOpenAssignedTickets counts tickets currently assigned to assigneeMemberID whose status is
// NOT closed — the agent-removal protection rule's own query ("currently assigned open
// tickets"). Interpreted strictly: any ticket not yet closed still needs its assignee (a resolved
// ticket can still be reopened by its reporter and would need the same agent again) — the
// stricter reading of an unclear transition-rule edge.
func (s *Store) CountOpenAssignedTickets(ctx context.Context, companyID, assigneeMemberID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM helpdesk.ticket
		WHERE company_id = $1 AND assignee_member_id = $2 AND status <> 'closed'`,
		pgFromUUID(companyID), pgFromUUID(assigneeMemberID),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("helpdesk: count open assigned tickets: %w", err)
	}
	return count, nil
}

// CountOpenAssignedTicketsForPosition is CountOpenAssignedTickets's position sibling: the
// same protection-rule query, scoped to a POSITION assignee rather than a member — DELETE
// /agents/positions/{id} refuses while open tickets are assigned to that position.
func (s *Store) CountOpenAssignedTicketsForPosition(ctx context.Context, companyID, positionID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM helpdesk.ticket
		WHERE company_id = $1 AND assignee_position_id = $2 AND status <> 'closed'`,
		pgFromUUID(companyID), pgFromUUID(positionID),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("helpdesk: count open assigned tickets for position: %w", err)
	}
	return count, nil
}

// CountOpenAssignedTicketsForGroup is CountOpenAssignedTickets's group sibling: the same
// protection-rule query, scoped to a GROUP assignee — the removal-protection rule for a group's
// agent binding (mirrors CountOpenAssignedTicketsForPosition).
func (s *Store) CountOpenAssignedTicketsForGroup(ctx context.Context, companyID, groupID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM helpdesk.ticket
		WHERE company_id = $1 AND assignee_group_id = $2 AND status <> 'closed'`,
		pgFromUUID(companyID), pgFromUUID(groupID),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("helpdesk: count open assigned tickets for group: %w", err)
	}
	return count, nil
}

// ---- comments (append-only) --------------------------------------------------------------------

type Comment struct {
	ID          uuid.UUID
	TicketID    uuid.UUID
	AuthorKcSub string
	Body        string
	CreatedAt   time.Time
}

// FindCommentByIdempotencyKey looks up a previously created comment by (ticketID, authorKcSub,
// idempotencyKey) — the handler calls this BEFORE creating a new comment, so a replayed
// create-comment request never creates a second row. Returns the stored payload hash (empty
// string for a row stored without a hash) alongside the comment.
func (s *Store) FindCommentByIdempotencyKey(ctx context.Context, ticketID uuid.UUID, authorKcSub, idempotencyKey string) (Comment, string, bool, error) {
	var c Comment
	var pgID, pgTicketID pgtype.UUID
	var hash *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, ticket_id, author_kcsub, body, created_at, idempotency_key_hash
		FROM helpdesk.comment WHERE ticket_id = $1 AND author_kcsub = $2 AND idempotency_key = $3`,
		pgFromUUID(ticketID), authorKcSub, idempotencyKey,
	).Scan(&pgID, &pgTicketID, &c.AuthorKcSub, &c.Body, &c.CreatedAt, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Comment{}, "", false, nil
		}
		return Comment{}, "", false, fmt.Errorf("helpdesk: find comment by idempotency key: %w", err)
	}
	c.ID, c.TicketID = uuidFromPg(pgID), uuidFromPg(pgTicketID)
	hashStr := ""
	if hash != nil {
		hashStr = *hash
	}
	return c, hashStr, true, nil
}

// CreateComment persists a new comment. idempotencyKey (may be "") is persisted alongside its
// payload hash for future replay detection via FindCommentByIdempotencyKey — this method itself
// does not replay/conflict-check (the handler already did).
func (s *Store) CreateComment(ctx context.Context, actor string, ticketID uuid.UUID, body, idempotencyKey string) (Comment, error) {
	if len(body) < 1 || len(body) > 10000 {
		return Comment{}, &ValidationError{Field: "body", Message: "must be 1..10000 characters"}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Comment{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var idemKey, idemHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		h := commentIdempotencyPayloadHash(ticketID, actor, body)
		idemHash = &h
	}

	var c Comment
	var pgID, pgTicketID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO helpdesk.comment (ticket_id, author_kcsub, body, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, ticket_id, author_kcsub, body, created_at`,
		pgFromUUID(ticketID), actor, body, idemKey, idemHash,
	).Scan(&pgID, &pgTicketID, &c.AuthorKcSub, &c.Body, &c.CreatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Comment{}, ErrIdempotencyConflict
		}
		return Comment{}, fmt.Errorf("helpdesk: create comment: %w", err)
	}
	c.ID, c.TicketID = uuidFromPg(pgID), uuidFromPg(pgTicketID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.comment.create", Subject: "helpdesk_ticket:" + ticketID.String(),
		Payload: map[string]any{"commentId": c.ID.String()},
	}); err != nil {
		return Comment{}, fmt.Errorf("helpdesk: audit comment create: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Comment{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return c, nil
}

func (s *Store) ListComments(ctx context.Context, ticketID uuid.UUID) ([]Comment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, ticket_id, author_kcsub, body, created_at
		FROM helpdesk.comment WHERE ticket_id = $1 ORDER BY created_at ASC`,
		pgFromUUID(ticketID),
	)
	if err != nil {
		return nil, fmt.Errorf("helpdesk: list comments: %w", err)
	}
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var c Comment
		var pgID, pgTicketID pgtype.UUID
		if err := rows.Scan(&pgID, &pgTicketID, &c.AuthorKcSub, &c.Body, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("helpdesk: scan comment: %w", err)
		}
		c.ID, c.TicketID = uuidFromPg(pgID), uuidFromPg(pgTicketID)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- agents (read-side index only — see file header) -------------------------------------------

// BindingKindMember / BindingKindPosition / BindingKindGroup are the three shapes helpdesk.agent
// can take: a per-member row (member_id/kcsub set), a per-position row (position_id/
// position_title set), or a per-group row (group_id/group_title set) —
// exactly one, enforced by the migration's CHECK constraint
// (agent_exactly_one_of_member_position_or_group).
const (
	BindingKindMember   = "member"
	BindingKindPosition = "position"
	BindingKindGroup    = "group"
)

type Agent struct {
	ID            uuid.UUID
	CompanyID     uuid.UUID
	MemberID      *uuid.UUID // set only for a member-bound row
	KcSub         string     // set only for a member-bound row
	PositionID    *uuid.UUID // set only for a position-bound row
	PositionTitle string     // set only for a position-bound row (display snapshot)
	GroupID       *uuid.UUID // set only for a group-bound row
	GroupTitle    string     // set only for a group-bound row (display snapshot)
	GrantedBy     string
	CreatedAt     time.Time
}

// BindingKind reports which of the three shapes this row is.
func (a Agent) BindingKind() string {
	switch {
	case a.PositionID != nil:
		return BindingKindPosition
	case a.GroupID != nil:
		return BindingKindGroup
	default:
		return BindingKindMember
	}
}

const agentColumns = `id, company_id, member_id, kcsub, position_id, position_title, group_id, group_title, granted_by, created_at`

func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	var pgID, pgCompanyID, pgMemberID, pgPositionID, pgGroupID pgtype.UUID
	var kcSub, positionTitle, groupTitle pgtype.Text
	if err := row.Scan(&pgID, &pgCompanyID, &pgMemberID, &kcSub, &pgPositionID, &positionTitle, &pgGroupID, &groupTitle, &a.GrantedBy, &a.CreatedAt); err != nil {
		return Agent{}, err
	}
	a.ID, a.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
	a.MemberID = pgconv.UUIDPtrFromPg(pgMemberID)
	if kcSub.Valid {
		a.KcSub = kcSub.String
	}
	a.PositionID = pgconv.UUIDPtrFromPg(pgPositionID)
	if positionTitle.Valid {
		a.PositionTitle = positionTitle.String
	}
	a.GroupID = pgconv.UUIDPtrFromPg(pgGroupID)
	if groupTitle.Valid {
		a.GroupTitle = groupTitle.String
	}
	return a, nil
}

// RecordAgent upserts the local MEMBER-bound index row. Caller MUST have already granted
// `company_module:<companyId>/helpdesk#editor @ user:<kcSub>` through AuthzClient.GrantAgent
// before calling this (store_approvers.go's own established ordering).
func (s *Store) RecordAgent(ctx context.Context, actor string, companyID, memberID uuid.UUID, kcSub, grantedByKcSub string) (Agent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		INSERT INTO helpdesk.agent (company_id, member_id, kcsub, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, member_id) DO UPDATE SET kcsub = EXCLUDED.kcsub
		RETURNING `+agentColumns,
		pgFromUUID(companyID), pgFromUUID(memberID), kcSub, grantedByKcSub,
	)
	a, err := scanAgent(row)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: record agent: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.grant", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"memberId": memberID.String()},
	}); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: audit agent grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return a, nil
}

// RemoveAgent deletes the local MEMBER-bound index row. Caller MUST have already revoked the
// corresponding authz tuple via AuthzClient.RevokeAgent, and MUST have already checked the
// protection rule (CountOpenAssignedTickets == 0), before calling this.
func (s *Store) RemoveAgent(ctx context.Context, actor string, companyID, memberID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `DELETE FROM helpdesk.agent WHERE company_id = $1 AND member_id = $2`, pgFromUUID(companyID), pgFromUUID(memberID))
	if err != nil {
		return fmt.Errorf("helpdesk: remove agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAgentNotFound
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.revoke", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"memberId": memberID.String()},
	}); err != nil {
		return fmt.Errorf("helpdesk: audit agent revoke: %w", err)
	}
	return tx.Commit(ctx)
}

// RecordAgentForPosition inserts the local POSITION-bound index row. It is called BEFORE the
// authz tuple grant (index-first-then-grant): the fail-safe direction is "visible-but-powerless,
// never powerful-but-invisible", and http.go's handleMakeAgent deletes the row again (via
// RemoveAgentForPosition) if the subsequent grant fails, so a failed grant never leaves an index
// row claiming access the tuple doesn't back.
func (s *Store) RecordAgentForPosition(ctx context.Context, actor string, companyID, positionID uuid.UUID, positionTitle, grantedByKcSub string) (Agent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		INSERT INTO helpdesk.agent (company_id, position_id, position_title, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, position_id) WHERE position_id IS NOT NULL
		DO UPDATE SET position_title = EXCLUDED.position_title
		RETURNING `+agentColumns,
		pgFromUUID(companyID), pgFromUUID(positionID), positionTitle, grantedByKcSub,
	)
	a, err := scanAgent(row)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: record position agent: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.grant", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"positionId": positionID.String()},
	}); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: audit position agent grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return a, nil
}

// RemoveAgentForPosition deletes the local POSITION-bound index row — either the deliberate
// revoke route (DELETE /agents/positions/{positionId}), or http.go's own compensating rollback
// when RecordAgentForPosition succeeded but the subsequent authz grant failed.
func (s *Store) RemoveAgentForPosition(ctx context.Context, actor string, companyID, positionID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `DELETE FROM helpdesk.agent WHERE company_id = $1 AND position_id = $2`, pgFromUUID(companyID), pgFromUUID(positionID))
	if err != nil {
		return fmt.Errorf("helpdesk: remove position agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAgentNotFound
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.revoke", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"positionId": positionID.String()},
	}); err != nil {
		return fmt.Errorf("helpdesk: audit position agent revoke: %w", err)
	}
	return tx.Commit(ctx)
}

// RecordAgentForGroup inserts the local GROUP-bound index row — the same
// index-first-then-grant ordering as RecordAgentForPosition.
func (s *Store) RecordAgentForGroup(ctx context.Context, actor string, companyID, groupID uuid.UUID, groupTitle, grantedByKcSub string) (Agent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx, `
		INSERT INTO helpdesk.agent (company_id, group_id, group_title, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (company_id, group_id) WHERE group_id IS NOT NULL
		DO UPDATE SET group_title = EXCLUDED.group_title
		RETURNING `+agentColumns,
		pgFromUUID(companyID), pgFromUUID(groupID), groupTitle, grantedByKcSub,
	)
	a, err := scanAgent(row)
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: record group agent: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.grant", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"groupId": groupID.String()},
	}); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: audit group agent grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Agent{}, fmt.Errorf("helpdesk: commit: %w", err)
	}
	return a, nil
}

// RemoveAgentForGroup deletes the local GROUP-bound index row — the deliberate revoke route
// (DELETE /agents/groups/{groupId}), or http.go's own compensating rollback when
// RecordAgentForGroup succeeded but the subsequent authz grant failed.
func (s *Store) RemoveAgentForGroup(ctx context.Context, actor string, companyID, groupID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("helpdesk: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `DELETE FROM helpdesk.agent WHERE company_id = $1 AND group_id = $2`, pgFromUUID(companyID), pgFromUUID(groupID))
	if err != nil {
		return fmt.Errorf("helpdesk: remove group agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAgentNotFound
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "helpdesk.agent.revoke", Subject: "company_module:" + companyModuleObjectID(companyID.String()),
		Payload: map[string]any{"groupId": groupID.String()},
	}); err != nil {
		return fmt.Errorf("helpdesk: audit group agent revoke: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) ListAgents(ctx context.Context, companyID uuid.UUID) ([]Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+agentColumns+`
		FROM helpdesk.agent WHERE company_id = $1 ORDER BY created_at ASC`,
		pgFromUUID(companyID),
	)
	if err != nil {
		return nil, fmt.Errorf("helpdesk: list agents: %w", err)
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("helpdesk: scan agent: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAgent(ctx context.Context, companyID, memberID uuid.UUID) (Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+agentColumns+`
		FROM helpdesk.agent WHERE company_id = $1 AND member_id = $2`,
		pgFromUUID(companyID), pgFromUUID(memberID),
	)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrAgentNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: get agent: %w", err)
	}
	return a, nil
}

// GetAgentForPosition looks up a position's own agent-binding row (if any) — the "is this
// position already an agent?" idempotency check http.go's handleMakeAgent uses before granting
// again (mirroring GetAgent's own use for the member path).
func (s *Store) GetAgentForPosition(ctx context.Context, companyID, positionID uuid.UUID) (Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+agentColumns+`
		FROM helpdesk.agent WHERE company_id = $1 AND position_id = $2`,
		pgFromUUID(companyID), pgFromUUID(positionID),
	)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrAgentNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: get position agent: %w", err)
	}
	return a, nil
}

// GetAgentForGroup looks up a group's own agent-binding row (if any) — the "is this group already
// an agent?" idempotency check http.go's handleMakeAgent uses before granting again (mirrors
// GetAgentForPosition's own use for the position path).
func (s *Store) GetAgentForGroup(ctx context.Context, companyID, groupID uuid.UUID) (Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+agentColumns+`
		FROM helpdesk.agent WHERE company_id = $1 AND group_id = $2`,
		pgFromUUID(companyID), pgFromUUID(groupID),
	)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrAgentNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("helpdesk: get group agent: %w", err)
	}
	return a, nil
}

// ---- audit (read-only; reads this module's own audit.helpdesk__events table) -------------------

type AuditEvent struct {
	OccurredAt time.Time
	Actor      string
	Action     string
	Subject    string
	Payload    map[string]any
}

// TicketAudit returns every audit event whose subject is exactly this ticket (create, assign,
// status transitions) — the ticket detail page's status timeline, built from audit events. Caller (http.go) MUST already have verified visibility before calling this.
func (s *Store) TicketAudit(ctx context.Context, ticketID uuid.UUID) ([]AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT occurred_at, actor, action, subject, payload
		FROM audit.helpdesk__events WHERE subject = $1 ORDER BY occurred_at ASC LIMIT 200`,
		"helpdesk_ticket:"+ticketID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("helpdesk: ticket audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var payload []byte
		if err := rows.Scan(&e.OccurredAt, &e.Actor, &e.Action, &e.Subject, &payload); err != nil {
			return nil, fmt.Errorf("helpdesk: scan audit event: %w", err)
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &e.Payload); err != nil {
				return nil, fmt.Errorf("helpdesk: decode audit payload: %w", err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
