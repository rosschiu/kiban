// SPDX-License-Identifier: Apache-2.0

// Package org implements the org service: the triangle. It owns org-unit tree facts
// (typed taxonomy = configuration, company = the sole tenancy/authz anchor), members
// (company-scoped persons, optional user link), and position slots (C-lite: position +
// assignment with validity windows). Facts only — anything ACTING on these facts is a module.
package org

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	authzstore "github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/pgconv"
)

// rowQuerier is the one-row read both pgx.Tx and *pgxpool.Pool offer — today() reads the
// tenant timezone through whichever the caller is already on.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// today returns the calendar date "now" (midnight UTC-normalised, as a DATE) in the tenant's
// timezone — `platform.tenant_defaults.timezone` (registry-owned, default 'UTC'; kiban_org has
// SELECT via migrations/registry/0015), read once per request on the caller's own tx/pool. This
// is the server-derived "now" every assign-NOW/end-NOW surface and the "current holder" list
// use (no caller-supplied dates, no CURRENT_DATE second clock). An unloadable zone name is an
// error, never a silent UTC fallback.
func (s *Store) today(ctx context.Context, db rowQuerier) (time.Time, error) {
	var tz string
	if err := db.QueryRow(ctx, `SELECT timezone FROM platform.tenant_defaults WHERE tenant_id = 'default'`).Scan(&tz); err != nil {
		return time.Time{}, fmt.Errorf("org: read tenant timezone: %w", err)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, fmt.Errorf("org: tenant timezone %q: %w", tz, err)
	}
	now := s.now().In(loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC), nil
}

// Store is the org service's data access layer: a pgx pool plus the sqlc-generated Queries
// built from it.
type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
	now   func() time.Time // the clock today() reads; tests inject a fixed instant
}

// NewStore wraps an already-connected pool (the caller owns its lifecycle: connect with the
// service's own kiban_org credentials) plus the audit writer for "audit.org__events" (member
// mutations audit their full changed-field set).
func NewStore(pool *pgxpool.Pool, auditWriter *audit.Writer) *Store {
	return &Store{pool: pool, audit: auditWriter, now: time.Now}
}

// Pool returns the underlying pool (used by http.go for the /ready liveness check).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (no runtime DDL, ever; migrations are applied out-of-band by `make migrate-org`, as
// the kiban owner role).
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_org`).Scan(&version)
	if err != nil {
		return fmt.Errorf(
			"org: migrations not applied (run `make migrate-org` against this database first): %w",
			err,
		)
	}
	if version <= 0 {
		return errors.New("org: migrations table present but at version 0 — run `make migrate-org`")
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------------------------

// ValidationError is a 422 VALIDATION_ERROR {field} condition — returned by both application-level input
// validation and by classifying a Postgres CHECK/trigger violation back to its field.
type ValidationError struct {
	Field   string
	Message string
}

// checkCompanyIsRoot enforces the glossary rule "a company is a root org unit and a root org
// unit is a company": company-typed units never have a parent, and no other
// type may sit at the top of a tree. The move trigger (migrations/org/0005) resolves "the
// company" of any unit as its topmost ancestor, so this is what makes that resolution correct.
func checkCompanyIsRoot(isCompany bool, parentID *uuid.UUID) error {
	switch {
	case isCompany && parentID != nil:
		return &ValidationError{Field: "parentId", Message: "a company org unit cannot have a parent"}
	case !isCompany && parentID == nil:
		return &ValidationError{Field: "parentId", Message: "only a company org unit can be a root; give this unit a parent"}
	}
	return nil
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("org: validation: field %s: %s", e.Field, e.Message)
}

// ErrConflict is a 409 CONFLICT condition: a unique or exclusion constraint violation (duplicate
// code, duplicate user link within a company, overlapping assignment).
var ErrConflict = errors.New("org: conflict")

var (
	ErrOrgUnitNotFound    = errors.New("org: org unit not found")
	ErrOrgUnitHasChildren = errors.New("org: org unit has children")
	ErrOrgUnitHasMembers  = errors.New("org: org unit has members")
	ErrMemberNotFound     = errors.New("org: member not found")
	ErrPositionNotFound   = errors.New("org: position not found")
	ErrAssignmentNotFound = errors.New("org: assignment not found")
	// ErrAssignmentAlreadyEnded is the 409 ASSIGNMENT_ALREADY_ENDED: EndAssignment on a window
	// whose valid_to is already set writes nothing (re-ending would rewrite history and revoke
	// the holder tuple a newer open assignment for the same pair depends on).
	ErrAssignmentAlreadyEnded = errors.New("org: assignment already ended")
)

// ErrMemberInactive is the 422 VALIDATION_ERROR for assign-NOW against an inactive member —
// assign-NOW never silently assigns an inactive member.
var ErrMemberInactive = &ValidationError{Field: "memberId", Message: "member must be active"}

// PositionBoundError is the 409 CONFLICT for deleting a position
// while any tuple still names `position:<id>#holder` as SUBJECT — i.e. at least one module
// binding (e.g. helpdesk's agent tier) still points at this position. Count is the number of such
// tuples, surfaced to the caller so the 409 is actionable. Position DELETE never cascade-revokes
// another module's grants to unblock itself.
type PositionBoundError struct {
	Count int
}

func (e *PositionBoundError) Error() string {
	return fmt.Sprintf("org: position is bound to %d module grant(s), delete refused", e.Count)
}

// ReferencedError is the 409 CONFLICT for a DELETE refused by a foreign key: the row is still
// referenced from Table (the referencing table's name, e.g. "position_assignment") — the
// opposite of the INSERT/UPDATE-side "referenced row does not exist" 422.
type ReferencedError struct {
	Table string
}

func (e *ReferencedError) Error() string {
	return fmt.Sprintf("org: still referenced by org.%s, delete refused", e.Table)
}

// classifyDeleteError is classifyPgError for DELETE statements: a foreign_key_violation there
// means "still referenced", a 409, not a missing parent.
func classifyDeleteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return &ReferencedError{Table: pgErr.TableName}
	}
	return classifyPgError(err)
}

// codeNamePattern is the company code rule, applied uniformly to every org_unit/member/position
// code.
var codeNamePattern = regexp.MustCompile(`^[A-Z0-9_-]{2,32}$`)

// normalizeCode applies the code normalization rule: trim, upper, spaces→-.
func normalizeCode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ToUpper(code)
	code = strings.Join(strings.Fields(code), "-")
	return code
}

func validateCode(field, code string) error {
	if !codeNamePattern.MatchString(code) {
		return &ValidationError{Field: field, Message: "must match ^[A-Z0-9_-]{2,32}$ after trim/upper/spaces→-"}
	}
	return nil
}

func validateNameLen(field, name string, min, max int) error {
	n := len(name)
	if n < min || n > max {
		return &ValidationError{Field: field, Message: fmt.Sprintf("length must be between %d and %d", min, max)}
	}
	return nil
}

// classifyPgError maps a raw Postgres error from a constraint/trigger to the store's own
// sentinel/ValidationError/ErrConflict shapes, so http.go never has to know constraint names.
func classifyPgError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23514": // check_violation (incl. the member-company-typed trigger, ERRCODE forced above)
		return &ValidationError{Field: fieldForConstraint(pgErr.ConstraintName), Message: pgErr.Message}
	case "23505": // unique_violation
		return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
	case "23P01": // exclusion_violation (overlapping position_assignment)
		return fmt.Errorf("%w: overlapping assignment", ErrConflict)
	case "23503": // foreign_key_violation
		return &ValidationError{Field: fieldForConstraint(pgErr.ConstraintName), Message: "referenced row does not exist"}
	default:
		return err
	}
}

func fieldForConstraint(constraint string) string {
	switch {
	case strings.Contains(constraint, "org_unit_code"):
		return "code"
	case strings.Contains(constraint, "org_unit_name"):
		return "name"
	case strings.Contains(constraint, "org_unit_parent"):
		return "parentId"
	case strings.Contains(constraint, "org_unit_type"):
		return "typeKey"
	case strings.Contains(constraint, "member_code"):
		return "code"
	case strings.Contains(constraint, "member_display_name"):
		return "displayName"
	case strings.Contains(constraint, "member_company_id"):
		return "companyId"
	case strings.Contains(constraint, "member_user_id"):
		return "userId"
	case strings.Contains(constraint, "position_assignment"):
		return "validFrom"
	case strings.Contains(constraint, "position_"):
		return "code"
	default:
		return constraint
	}
}

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func pgFromUUIDPtr(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

func pgDate(t time.Time) pgtype.Date {
	return pgtype.Date{Time: t, Valid: true}
}

func pgDatePtr(t *time.Time) pgtype.Date {
	if t == nil {
		return pgtype.Date{}
	}
	return pgtype.Date{Time: *t, Valid: true}
}

func timePtrFromPgDate(d pgtype.Date) *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.Time
	return &t
}

// ---- org_unit ---------------------------------------------------------------------------------

// OrgUnit is the API-facing shape of an org.org_unit row.
type OrgUnit struct {
	ID       uuid.UUID
	TypeKey  string
	ParentID *uuid.UUID
	Code     string
	Name     string
	IsActive bool
	Depth    int
}

func orgUnitFromRow(r OrgOrgUnit) OrgUnit {
	return OrgUnit{
		ID:       uuidFromPg(r.ID),
		TypeKey:  r.TypeKey,
		ParentID: pgconv.UUIDPtrFromPg(r.ParentID),
		Code:     r.Code,
		Name:     r.Name,
		IsActive: r.IsActive,
	}
}

// orgUnitFields captures an org unit row's own fields for the audit payload (mirrors
// memberFields).
func orgUnitFields(u OrgUnit) map[string]any {
	var parentID any
	if u.ParentID != nil {
		parentID = u.ParentID.String()
	}
	return map[string]any{
		"typeKey":  u.TypeKey,
		"parentId": parentID,
		"code":     u.Code,
		"name":     u.Name,
		"isActive": u.IsActive,
	}
}

// CreateOrgUnit creates a new org unit, auditing in the SAME transaction as the state change
// — an audit failure rolls back the insert (fail closed).
// code/name are normalized/validated here (application layer) before insert; the DB CHECK
// constraints are the storage-level backstop.
func (s *Store) CreateOrgUnit(ctx context.Context, actor, typeKey string, parentID *uuid.UUID, code, name string, isActive bool) (OrgUnit, error) {
	code = normalizeCode(code)
	name = strings.TrimSpace(name)
	if err := validateCode("code", code); err != nil {
		return OrgUnit{}, err
	}
	if err := validateNameLen("name", name, 2, 120); err != nil {
		return OrgUnit{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OrgUnit{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	unitType, err := q.GetOrgUnitType(ctx, typeKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrgUnit{}, &ValidationError{Field: "typeKey", Message: "unknown org unit type"}
		}
		return OrgUnit{}, fmt.Errorf("org: look up org_unit_type %q: %w", typeKey, err)
	}
	if err := checkCompanyIsRoot(unitType.IsCompany, parentID); err != nil {
		return OrgUnit{}, err
	}
	row, err := q.CreateOrgUnit(ctx, CreateOrgUnitParams{
		TypeKey: typeKey, ParentID: pgFromUUIDPtr(parentID), Code: code, Name: name, IsActive: isActive,
	})
	if err != nil {
		return OrgUnit{}, classifyPgError(err)
	}
	unit := orgUnitFromRow(row)
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.unit.create", Subject: "org_unit:" + unit.ID.String(), Payload: orgUnitFields(unit),
	}); err != nil {
		return OrgUnit{}, fmt.Errorf("org: audit mutation: %w", err)
	}

	// A new COMPANY (org_unit_type.is_company = true) gets every currently
	// installed+enabled module's default admin grant in this SAME transaction — atomic with the
	// unit's own creation, so a company is never even briefly visible without an accountable
	// admin. A non-company unit (a plain taxonomy node) or an inactive one is untouched.
	if isActive {
		if unitType.IsCompany {
			if err := defaultGrantNewCompanyTx(ctx, tx, unit.ID.String()); err != nil {
				return OrgUnit{}, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return OrgUnit{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return unit, nil
}

// GetOrgUnit looks up an org unit by id.
func (s *Store) GetOrgUnit(ctx context.Context, id uuid.UUID) (OrgUnit, error) {
	q := New(s.pool)
	row, err := q.GetOrgUnit(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrgUnit{}, ErrOrgUnitNotFound
		}
		return OrgUnit{}, fmt.Errorf("org: get org unit: %w", err)
	}
	return orgUnitFromRow(row), nil
}

// Subtree returns id's subtree (itself plus every descendant), depth-bounded 32, via the
// recursive CTE — powers GET /internal/org/units/{id}/subtree.
func (s *Store) Subtree(ctx context.Context, id uuid.UUID) ([]OrgUnit, error) {
	q := New(s.pool)
	rows, err := q.SubtreeOrgUnits(ctx, pgFromUUID(id))
	if err != nil {
		return nil, fmt.Errorf("org: subtree: %w", err)
	}
	out := make([]OrgUnit, 0, len(rows))
	for _, r := range rows {
		out = append(out, OrgUnit{
			ID: uuidFromPg(r.ID), TypeKey: r.TypeKey, ParentID: pgconv.UUIDPtrFromPg(r.ParentID),
			Code: r.Code, Name: r.Name, IsActive: r.IsActive, Depth: int(r.Depth),
		})
	}
	return out, nil
}

// UpdateOrgUnit updates parent/code/name/is_active. type_key is immutable (the query has no
// type_key column at all). Moving a unit under a new parent is
// validated as cycle-proof: the candidate parent must not already be in this unit's own subtree
// (which would make it its own descendant's descendant).
func (s *Store) UpdateOrgUnit(ctx context.Context, actor string, id uuid.UUID, parentID *uuid.UUID, code, name string, isActive bool) (OrgUnit, error) {
	code = normalizeCode(code)
	name = strings.TrimSpace(name)
	if err := validateCode("code", code); err != nil {
		return OrgUnit{}, err
	}
	if err := validateNameLen("name", name, 2, 120); err != nil {
		return OrgUnit{}, err
	}
	if parentID != nil && *parentID == id {
		return OrgUnit{}, &ValidationError{Field: "parentId", Message: "an org unit cannot be its own parent"}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OrgUnit{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// Acquire the transaction-scoped advisory lock FIRST, before any snapshot-dependent validation
	// this method performs below — otherwise two concurrent UpdateOrgUnit calls (or an
	// UpdateOrgUnit racing a CreatePosition/UpdatePosition/AssignNow) each read a
	// consistent-but-stale MVCC snapshot, pass their own check, and jointly commit an inconsistent
	// state (e.g. a sibling-swap cycle, or a unit move racing a position create).
	// Migration 0006's org_unit trigger acquires the identical lock for direct-SQL writers; this
	// call is the store-layer half for app-level callers going through this method.
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return OrgUnit{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}

	q := New(s.pool).WithTx(tx)

	if parentID != nil {
		subtree, err := q.SubtreeOrgUnits(ctx, pgFromUUID(id))
		if err != nil {
			return OrgUnit{}, fmt.Errorf("org: subtree for move check: %w", err)
		}
		for _, u := range subtree {
			if uuidFromPg(u.ID) == *parentID {
				return OrgUnit{}, &ValidationError{Field: "parentId", Message: "would create a cycle: candidate parent is already in this unit's subtree"}
			}
		}
	}

	// Store-level UX check ahead of migration 0005's trigger backstop. Only relevant
	// when parent_id is actually changing (UpdateOrgUnit's query always sets parent_id, so "no
	// change" means the new value equals the row's current one).
	existing, err := q.GetOrgUnit(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrgUnit{}, ErrOrgUnitNotFound
		}
		return OrgUnit{}, fmt.Errorf("org: get org unit for move check: %w", err)
	}
	existingType, err := q.GetOrgUnitType(ctx, existing.TypeKey)
	if err != nil {
		return OrgUnit{}, fmt.Errorf("org: look up org_unit_type %q: %w", existing.TypeKey, err)
	}
	if err := checkCompanyIsRoot(existingType.IsCompany, parentID); err != nil {
		return OrgUnit{}, err
	}
	oldParentID := pgconv.UUIDPtrFromPg(existing.ParentID)
	if !uuidPtrEqual(oldParentID, parentID) {
		oldRoot, err := s.resolveRootCompany(ctx, tx, id)
		if err != nil {
			return OrgUnit{}, err
		}
		var newRoot uuid.UUID
		if parentID == nil {
			newRoot = id
		} else {
			newRoot, err = s.resolveRootCompany(ctx, tx, *parentID)
			if err != nil {
				return OrgUnit{}, err
			}
		}
		if oldRoot != newRoot {
			hasPositions, err := s.subtreeHasPositions(ctx, tx, id)
			if err != nil {
				return OrgUnit{}, err
			}
			if hasPositions {
				return OrgUnit{}, &ValidationError{
					Field:   "parentId",
					Message: "cannot move this org unit under a different company while its subtree still holds position(s) — reassign or delete them first",
				}
			}
		}
	}

	row, err := q.UpdateOrgUnit(ctx, UpdateOrgUnitParams{
		ID: pgFromUUID(id), ParentID: pgFromUUIDPtr(parentID), Code: code, Name: name, IsActive: isActive,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OrgUnit{}, ErrOrgUnitNotFound
		}
		return OrgUnit{}, classifyPgError(err)
	}
	unit := orgUnitFromRow(row)
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.unit.update", Subject: "org_unit:" + id.String(), Payload: orgUnitFields(unit),
	}); err != nil {
		return OrgUnit{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	// A company activated here (created inactive, or re-activated) gets its default module
	// grants now — the same default-ONCE writer CreateOrgUnit uses for an active company, in the
	// same transaction. Registry's Seed would otherwise only converge it at the next boot.
	if existingType.IsCompany && !existing.IsActive && unit.IsActive {
		if err := defaultGrantNewCompanyTx(ctx, tx, unit.ID.String()); err != nil {
			return OrgUnit{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return OrgUnit{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return unit, nil
}

// DeleteOrgUnit deletes an org unit — guarded: cannot delete a unit with children or members.
// The guards run inside the delete transaction, after locking the unit row FOR UPDATE: a
// concurrent child/member insert takes FOR KEY SHARE on this row through its FK, so it either
// commits before the lock (the guard sees it → 422) or waits and then fails its FK (the unit is
// gone). Anything else still referencing the unit (positions, groups) surfaces as the FK's
// ReferencedError (409). Audited in the same transaction as the delete.
func (s *Store) DeleteOrgUnit(ctx context.Context, actor string, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if _, err := tx.Exec(ctx, `SELECT 1 FROM org.org_unit WHERE id = $1 FOR UPDATE`, pgFromUUID(id)); err != nil {
		return fmt.Errorf("org: lock org unit: %w", err)
	}
	txq := New(s.pool).WithTx(tx)
	children, err := txq.CountOrgUnitChildren(ctx, pgFromUUID(id))
	if err != nil {
		return fmt.Errorf("org: count children: %w", err)
	}
	if children > 0 {
		return ErrOrgUnitHasChildren
	}
	members, err := txq.CountMembersForCompany(ctx, pgFromUUID(id))
	if err != nil {
		return fmt.Errorf("org: count members: %w", err)
	}
	if members > 0 {
		return ErrOrgUnitHasMembers
	}

	affected, err := txq.DeleteOrgUnit(ctx, pgFromUUID(id))
	if err != nil {
		return classifyDeleteError(err)
	}
	if affected == 0 {
		return ErrOrgUnitNotFound
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.unit.delete", Subject: "org_unit:" + id.String(),
	}); err != nil {
		return fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("org: commit tx: %w", err)
	}
	return nil
}

// ---- member -------------------------------------------------------------------------------

// Member is the API-facing shape of an org.member row, joined with identity.user_read_v when a
// user is linked (member directory read).
type Member struct {
	ID          uuid.UUID
	CompanyID   uuid.UUID
	Code        string
	DisplayName string
	Email       string
	UserID      *uuid.UUID
	IsActive    bool

	// Linked-user display fields (empty when UserID is nil) — never fetched per-row.
	UserKcSub             string
	UserEmail             string
	UserPreferredUsername string
	UserLifecycle         string
}

func memberFromRow(r OrgMember) Member {
	return Member{
		ID: uuidFromPg(r.ID), CompanyID: uuidFromPg(r.CompanyID), Code: r.Code,
		DisplayName: r.DisplayName, Email: pgconv.DerefStr(r.Email), UserID: pgconv.UUIDPtrFromPg(r.UserID), IsActive: r.IsActive,
	}
}

func memberFromJoinRow(id, companyID, userID pgtype.UUID, code, displayName string, email *string, isActive bool,
	userKcSub, userEmail, userPreferredUsername, userLifecycle *string,
) Member {
	return Member{
		ID: uuidFromPg(id), CompanyID: uuidFromPg(companyID), Code: code, DisplayName: displayName,
		Email: pgconv.DerefStr(email), UserID: pgconv.UUIDPtrFromPg(userID), IsActive: isActive,
		UserKcSub: pgconv.DerefStr(userKcSub), UserEmail: pgconv.DerefStr(userEmail),
		UserPreferredUsername: pgconv.DerefStr(userPreferredUsername), UserLifecycle: pgconv.DerefStr(userLifecycle),
	}
}

// memberFields captures a member row's own (non-identity) fields for the full-changed-field
// audit payload.
func memberFields(m Member) map[string]any {
	var userID any
	if m.UserID != nil {
		userID = m.UserID.String()
	}
	return map[string]any{
		"code":        m.Code,
		"displayName": m.DisplayName,
		"email":       m.Email,
		"userId":      userID,
		"isActive":    m.IsActive,
	}
}

// auditMemberMutation writes the full changed-field set (before AND after) for a
// member mutation, in the SAME transaction as the state change.
func (s *Store) auditMemberMutation(ctx context.Context, tx pgx.Tx, actor, action string, memberID uuid.UUID, before, after Member) error {
	return s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: action, Subject: "member:" + memberID.String(),
		Payload: map[string]any{"before": memberFields(before), "after": memberFields(after)},
	})
}

// CreateMember creates a member, auditing the full field set in the same transaction.
func (s *Store) CreateMember(ctx context.Context, actor string, companyID uuid.UUID, code, displayName, email string, isActive bool) (Member, error) {
	code = normalizeCode(code)
	displayName = strings.TrimSpace(displayName)
	if err := validateCode("code", code); err != nil {
		return Member{}, err
	}
	if err := validateNameLen("displayName", displayName, 1, 120); err != nil {
		return Member{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	row, err := q.CreateMember(ctx, CreateMemberParams{
		CompanyID: pgFromUUID(companyID), Code: code, DisplayName: displayName, Email: pgconv.StrOrNil(email), IsActive: isActive,
	})
	if err != nil {
		return Member{}, classifyPgError(err)
	}
	after := memberFromRow(row)
	if after.IsActive {
		if err := authzstore.Grant(ctx, tx, actor, "", companyMemberTuple(companyID, after.ID)); err != nil {
			return Member{}, fmt.Errorf("org: grant company member tuple: %w", err)
		}
	}
	if err := s.auditMemberMutation(ctx, tx, actor, "org.member.create", after.ID, Member{}, after); err != nil {
		return Member{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Member{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return after, nil
}

// companyMemberTuple is the membership fact `company:<companyId>#member @
// member:<memberId>#mapped_user` — granted while a member row is active, revoked when it is
// deactivated (CreateMember/UpdateMember), always in the SAME transaction as the row and its
// audit event, the pattern `position#holder` uses. The `#mapped_user` userset subject means the
// fact resolves to a user only while the member is ALSO linked (LinkUser/UnlinkUser maintain
// that half), so `company_module#member` (base model: `member from company`) answers true for
// exactly the active, linked members of the module's company.
func companyMemberTuple(companyID, memberID uuid.UUID) authzstore.Tuple {
	return authzstore.Tuple{
		ObjectType: "company", ObjectID: companyID.String(), Relation: "member",
		SubjectType: "member", SubjectID: memberID.String(), SubjectRelation: "mapped_user",
	}
}

// orgObjectCompanyTuple is `<objType>:<id>#company @ company:<companyId>` — the anchor the
// authz decision layer binds a position/group object check to the request's company through
// (the company-binding rule). Written in the same transaction as the row; positions and groups never
// change company, so it is only ever granted at create and revoked at delete.
func orgObjectCompanyTuple(objType string, id, companyID uuid.UUID) authzstore.Tuple {
	return authzstore.Tuple{
		ObjectType: objType, ObjectID: id.String(), Relation: "company",
		SubjectType: "company", SubjectID: companyID.String(),
	}
}

// GetMember looks up a member by id, joined with identity.user_read_v for linked-user display
// fields — a single SQL query, never a per-row identity call.
func (s *Store) GetMember(ctx context.Context, id uuid.UUID) (Member, error) {
	q := New(s.pool)
	row, err := q.GetMemberWithUser(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrMemberNotFound
		}
		return Member{}, fmt.Errorf("org: get member: %w", err)
	}
	return memberFromJoinRow(row.ID, row.CompanyID, row.UserID, row.Code, row.DisplayName, row.Email, row.IsActive,
		row.UserKcSub, row.UserEmail, row.UserPreferredUsername, row.UserLifecycle), nil
}

// ListMembers returns companyID's member directory, page/pageSize (default 1/25, clamp 1..100),
// joined with identity.user_read_v — filtered/paginated in SQL, never
// in-memory.
func (s *Store) ListMembers(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]Member, int, error) {
	page, pageSize = clampPage(page, pageSize)
	q := New(s.pool)

	total, err := q.CountMembers(ctx, pgFromUUID(companyID))
	if err != nil {
		return nil, 0, fmt.Errorf("org: count members: %w", err)
	}
	rows, err := q.ListMembers(ctx, ListMembersParams{
		CompanyID: pgFromUUID(companyID), Limit: int32(pageSize), Offset: int32((page - 1) * pageSize),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("org: list members: %w", err)
	}
	out := make([]Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, memberFromJoinRow(r.ID, r.CompanyID, r.UserID, r.Code, r.DisplayName, r.Email, r.IsActive,
			r.UserKcSub, r.UserEmail, r.UserPreferredUsername, r.UserLifecycle))
	}
	return out, int(total), nil
}

// Pagination bounds: page 1..maxPage, pageSize 1..maxPageSize. Handlers reject an over-limit
// value with 400 (pageParams); the store clamps as a backstop so an OFFSET can never overflow
// int32 (maxPage*maxPageSize = 1e6).
const (
	maxPage     = 10_000
	maxPageSize = 100
)

func clampPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if page > maxPage {
		page = maxPage
	}
	if pageSize < 1 {
		pageSize = 25
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

// UpdateMember updates display_name/email/is_active, auditing the full before/after field set
// in the same transaction. email is the only PII field (field-policy-eligible).
func (s *Store) UpdateMember(ctx context.Context, actor string, id uuid.UUID, displayName, email string, isActive bool) (Member, error) {
	displayName = strings.TrimSpace(displayName)
	if err := validateNameLen("displayName", displayName, 1, 120); err != nil {
		return Member{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	beforeRow, err := q.GetMember(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrMemberNotFound
		}
		return Member{}, fmt.Errorf("org: get member: %w", err)
	}
	before := memberFromRow(beforeRow)

	row, err := q.UpdateMember(ctx, UpdateMemberParams{ID: pgFromUUID(id), DisplayName: displayName, Email: pgconv.StrOrNil(email), IsActive: isActive})
	if err != nil {
		return Member{}, classifyPgError(err)
	}
	after := memberFromRow(row)
	switch {
	case !before.IsActive && after.IsActive: // reactivate
		if err := authzstore.Grant(ctx, tx, actor, "", companyMemberTuple(after.CompanyID, id)); err != nil {
			return Member{}, fmt.Errorf("org: grant company member tuple: %w", err)
		}
	case before.IsActive && !after.IsActive: // deactivate — via the SECURITY DEFINER seam (org has no DELETE on authz.tuple)
		if err := authzstore.RevokePositionOrMemberTuple(ctx, tx, actor, "", companyMemberTuple(after.CompanyID, id)); err != nil {
			return Member{}, fmt.Errorf("org: revoke company member tuple: %w", err)
		}
	}
	if err := s.auditMemberMutation(ctx, tx, actor, "org.member.update", id, before, after); err != nil {
		return Member{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Member{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return after, nil
}

// IdentityStateChecker is the seam LinkUser calls to validate a user exists over identity's
// state endpoint, not by trusting input — satisfied by identityclient.Client in production,
// faked with httptest in tests.
type IdentityStateChecker interface {
	// UserExists reports whether kcSub resolves to a live identity.user_account (any lifecycle
	// state counts as "exists" — LinkUser only needs to know the account is real, not that it's
	// active). A non-nil error means the check could not be completed (identity unreachable);
	// callers must treat that as "not confirmed", never as "exists".
	UserExists(ctx context.Context, kcSub string) (bool, error)
}

// ErrUserNotConfirmed is returned by LinkUser when identity's live state check could not confirm
// the kcSub resolves to a real account (either identity said not-found, or identity was
// unreachable — this call never trusts the input).
var ErrUserNotConfirmed = &ValidationError{Field: "kcSub", Message: "identity could not confirm this user exists"}

// LinkUser links memberID to the identity user identified by kcSub. It NEVER trusts kcSub as
// given: it first confirms the account exists via an HTTP call to identity (checker), then
// resolves the internal user_id via the published identity.user_read_v view — the only way org
// reads identity data — before writing the FK. UNIQUE(company_id, user_id) rejects a second member linking the same user in the same company.
func (s *Store) LinkUser(ctx context.Context, actor string, checker IdentityStateChecker, memberID uuid.UUID, kcSub string) (Member, error) {
	exists, err := checker.UserExists(ctx, kcSub)
	if err != nil || !exists {
		return Member{}, ErrUserNotConfirmed
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	identityUser, err := q.GetIdentityUserByKcSub(ctx, kcSub)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrUserNotConfirmed
		}
		return Member{}, fmt.Errorf("org: resolve identity user: %w", err)
	}

	beforeRow, err := q.GetMember(ctx, pgFromUUID(memberID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrMemberNotFound
		}
		return Member{}, fmt.Errorf("org: get member: %w", err)
	}
	before := memberFromRow(beforeRow)

	row, err := q.LinkMemberUser(ctx, LinkMemberUserParams{ID: pgFromUUID(memberID), UserID: identityUser.ID})
	if err != nil {
		return Member{}, classifyPgError(err)
	}
	after := memberFromRow(row)
	// The joined identity fields are already in hand from the GetIdentityUserByKcSub call above
	// — no need for a second query to build the directory-read shape callers expect back.
	after.UserKcSub = identityUser.KcSub
	after.UserEmail = pgconv.DerefStr(identityUser.Email)
	after.UserPreferredUsername = pgconv.DerefStr(identityUser.PreferredUsername)
	after.UserLifecycle = identityUser.Lifecycle

	// The member-bridge tuple: grant
	// `member:<memberId>#mapped_user @ user:<kcSub>` in the SAME transaction as the link row
	// write — the base model's dormant `member.mapped_user` relation, put to work.
	if err := authzstore.Grant(ctx, tx, actor, "", authzstore.Tuple{
		ObjectType: "member", ObjectID: memberID.String(), Relation: "mapped_user",
		SubjectType: "user", SubjectID: identityUser.KcSub,
	}); err != nil {
		return Member{}, fmt.Errorf("org: grant member mapped_user tuple: %w", err)
	}

	if err := s.auditMemberMutation(ctx, tx, actor, "org.member.link_user", memberID, before, after); err != nil {
		return Member{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Member{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return after, nil
}

// UnlinkUser clears memberID's user link.
func (s *Store) UnlinkUser(ctx context.Context, actor string, memberID uuid.UUID) (Member, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	// The JOINED read (not plain GetMember) so before.UserKcSub is populated when a
	// user is currently linked — the revoke below needs the kcSub the mapped_user tuple's
	// subject was granted under, not just the fact that a link existed.
	beforeRow, err := q.GetMemberWithUser(ctx, pgFromUUID(memberID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrMemberNotFound
		}
		return Member{}, fmt.Errorf("org: get member: %w", err)
	}
	before := memberFromJoinRow(beforeRow.ID, beforeRow.CompanyID, beforeRow.UserID, beforeRow.Code, beforeRow.DisplayName,
		beforeRow.Email, beforeRow.IsActive, beforeRow.UserKcSub, beforeRow.UserEmail, beforeRow.UserPreferredUsername, beforeRow.UserLifecycle)

	row, err := q.UnlinkMemberUser(ctx, pgFromUUID(memberID))
	if err != nil {
		return Member{}, classifyPgError(err)
	}
	after := memberFromRow(row)

	// Revoke the mapped_user tuple in the SAME transaction — via the SECURITY
	// DEFINER function (org has no DELETE grant on authz.tuple). Only when a user was actually
	// linked before this call (before.UserID != nil); an already-unlinked member has nothing to
	// revoke.
	if before.UserID != nil && before.UserKcSub != "" {
		if err := authzstore.RevokePositionOrMemberTuple(ctx, tx, actor, "", authzstore.Tuple{
			ObjectType: "member", ObjectID: memberID.String(), Relation: "mapped_user",
			SubjectType: "user", SubjectID: before.UserKcSub,
		}); err != nil {
			return Member{}, fmt.Errorf("org: revoke member mapped_user tuple: %w", err)
		}
	}

	if err := s.auditMemberMutation(ctx, tx, actor, "org.member.unlink_user", memberID, before, after); err != nil {
		return Member{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Member{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return after, nil
}

// ---- position / position_assignment --------------------------------------------------------

// Position is the API-facing shape of an org.position row.
type Position struct {
	ID        uuid.UUID
	CompanyID uuid.UUID
	Code      string
	Title     string
	OrgUnitID uuid.UUID
}

func positionFromRow(r OrgPosition) Position {
	return Position{ID: uuidFromPg(r.ID), CompanyID: uuidFromPg(r.CompanyID), Code: r.Code, Title: r.Title, OrgUnitID: uuidFromPg(r.OrgUnitID)}
}

// Assignment is the API-facing shape of an org.position_assignment row.
type Assignment struct {
	ID         uuid.UUID
	PositionID uuid.UUID
	MemberID   uuid.UUID
	ValidFrom  time.Time
	ValidTo    *time.Time
}

func assignmentFromRow(r OrgPositionAssignment) Assignment {
	return Assignment{
		ID: uuidFromPg(r.ID), PositionID: uuidFromPg(r.PositionID), MemberID: uuidFromPg(r.MemberID),
		ValidFrom: r.ValidFrom.Time, ValidTo: timePtrFromPgDate(r.ValidTo),
	}
}

// uuidPtrEqual reports whether two optional org-unit ids denote the same parent: both nil (root),
// or both non-nil with equal values.
func uuidPtrEqual(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// resolveRootCompany walks orgUnitID's ancestor chain (parent_id, inclusive of orgUnitID itself)
// to its topmost ancestor (parent_id IS NULL — the company, per 0002's org_unit comment
// convention) — the store-layer mirror of migration 0005's
// org.validate_org_unit_move_company() trigger.
func (s *Store) resolveRootCompany(ctx context.Context, tx pgx.Tx, orgUnitID uuid.UUID) (uuid.UUID, error) {
	const q = `
		WITH RECURSIVE chain AS (
			SELECT id, parent_id FROM org.org_unit WHERE id = $1
			UNION ALL
			SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
		)
		SELECT id FROM chain WHERE parent_id IS NULL
	`
	var row pgtype.UUID
	if err := tx.QueryRow(ctx, q, pgFromUUID(orgUnitID)).Scan(&row); err != nil {
		return uuid.UUID{}, fmt.Errorf("org: resolve root company: %w", err)
	}
	return uuidFromPg(row), nil
}

// subtreeHasPositions reports whether orgUnitID's subtree (itself plus every descendant) holds
// any org.position row — the cross-company move blocker: an empty subtree may re-home across
// companies freely, positions are what block a cross-company move.
func (s *Store) subtreeHasPositions(ctx context.Context, tx pgx.Tx, orgUnitID uuid.UUID) (bool, error) {
	const q = `
		WITH RECURSIVE subtree AS (
			SELECT id FROM org.org_unit WHERE id = $1
			UNION ALL
			SELECT u.id FROM org.org_unit u JOIN subtree s ON u.parent_id = s.id
		)
		SELECT EXISTS (SELECT 1 FROM org.position p JOIN subtree s ON p.org_unit_id = s.id)
	`
	var exists bool
	if err := tx.QueryRow(ctx, q, pgFromUUID(orgUnitID)).Scan(&exists); err != nil {
		return false, fmt.Errorf("org: check subtree has positions: %w", err)
	}
	return exists, nil
}

// orgUnitUnderCompany reports whether orgUnitID's ancestor chain (parent_id, inclusive of
// orgUnitID itself) reaches companyID — the store-layer mirror of migration 0004's
// org.validate_position_company() trigger: this is the UX-facing 422 check, the trigger is the
// backstop that still applies to any direct-SQL writer.
func (s *Store) orgUnitUnderCompany(ctx context.Context, tx pgx.Tx, orgUnitID, companyID uuid.UUID) (bool, error) {
	const q = `
		WITH RECURSIVE chain AS (
			SELECT id, parent_id FROM org.org_unit WHERE id = $1
			UNION ALL
			SELECT u.id, u.parent_id FROM org.org_unit u JOIN chain c ON u.id = c.parent_id
		)
		SELECT EXISTS (SELECT 1 FROM chain WHERE id = $2)
	`
	var exists bool
	if err := tx.QueryRow(ctx, q, pgFromUUID(orgUnitID), pgFromUUID(companyID)).Scan(&exists); err != nil {
		return false, fmt.Errorf("org: check org unit under company: %w", err)
	}
	return exists, nil
}

// memberCompanyID looks up memberID's company_id — the store-layer mirror half of
// migration 0004's org.validate_assignment_company() trigger. found=false (not an error) means
// no such member row; callers must treat that as "cannot confirm the relationship", never as a
// match, and let the normal not-found/FK path handle the missing row.
func (s *Store) memberCompanyID(ctx context.Context, tx pgx.Tx, memberID uuid.UUID) (companyID uuid.UUID, found bool, err error) {
	const q = `SELECT company_id FROM org.member WHERE id = $1`
	var row pgtype.UUID
	if err := tx.QueryRow(ctx, q, pgFromUUID(memberID)).Scan(&row); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.UUID{}, false, nil
		}
		return uuid.UUID{}, false, fmt.Errorf("org: lookup member company: %w", err)
	}
	return uuidFromPg(row), true, nil
}

// positionFields captures a position row's own fields for the audit payload.
func positionFields(p Position) map[string]any {
	return map[string]any{
		"companyId": p.CompanyID.String(), "code": p.Code, "title": p.Title, "orgUnitId": p.OrgUnitID.String(),
	}
}

// CreatePosition creates a position slot, auditing in the same transaction.
func (s *Store) CreatePosition(ctx context.Context, actor string, companyID uuid.UUID, code, title string, orgUnitID uuid.UUID) (Position, error) {
	code = normalizeCode(code)
	title = strings.TrimSpace(title)
	if err := validateCode("code", code); err != nil {
		return Position{}, err
	}
	if err := validateNameLen("title", title, 1, 120); err != nil {
		return Position{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Position{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// Acquire the lock before the snapshot-dependent orgUnitUnderCompany check below — see
	// UpdateOrgUnit for the full rationale (this is the "position create ∥ unit move" half).
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return Position{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}

	// The store-level UX check ahead of the DB trigger backstop (migration 0004).
	under, err := s.orgUnitUnderCompany(ctx, tx, orgUnitID, companyID)
	if err != nil {
		return Position{}, err
	}
	if !under {
		return Position{}, &ValidationError{Field: "orgUnitId", Message: "org unit must sit beneath companyId in the org_unit tree"}
	}

	q := New(s.pool).WithTx(tx)
	row, err := q.CreatePosition(ctx, CreatePositionParams{CompanyID: pgFromUUID(companyID), Code: code, Title: title, OrgUnitID: pgFromUUID(orgUnitID)})
	if err != nil {
		return Position{}, classifyPgError(err)
	}
	position := positionFromRow(row)
	if err := authzstore.Grant(ctx, tx, actor, "", orgObjectCompanyTuple("position", position.ID, companyID)); err != nil {
		return Position{}, fmt.Errorf("org: grant position company tuple: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.position.create", Subject: "position:" + position.ID.String(), Payload: positionFields(position),
	}); err != nil {
		return Position{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Position{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return position, nil
}

// GetPosition looks up a position by id.
func (s *Store) GetPosition(ctx context.Context, id uuid.UUID) (Position, error) {
	q := New(s.pool)
	row, err := q.GetPosition(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Position{}, ErrPositionNotFound
		}
		return Position{}, fmt.Errorf("org: get position: %w", err)
	}
	return positionFromRow(row), nil
}

// ListPositions returns companyID's positions, paginated.
func (s *Store) ListPositions(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]Position, int, error) {
	page, pageSize = clampPage(page, pageSize)
	q := New(s.pool)

	total, err := q.CountPositions(ctx, pgFromUUID(companyID))
	if err != nil {
		return nil, 0, fmt.Errorf("org: count positions: %w", err)
	}
	rows, err := q.ListPositions(ctx, ListPositionsParams{CompanyID: pgFromUUID(companyID), Limit: int32(pageSize), Offset: int32((page - 1) * pageSize)})
	if err != nil {
		return nil, 0, fmt.Errorf("org: list positions: %w", err)
	}
	out := make([]Position, 0, len(rows))
	for _, r := range rows {
		out = append(out, positionFromRow(r))
	}
	return out, int(total), nil
}

// PositionWithHolder is the admin-list shape: a position plus its CURRENT assignment (nil when
// the position has no holder today) — the fields the UI needs to END a tenure.
type PositionWithHolder struct {
	Position
	AssignmentID       *uuid.UUID
	AssignmentMemberID *uuid.UUID
	HolderDisplayName  *string
}

// ListPositionsWithHolder is ListPositions plus each row's current assignment — the admin
// surface. Paginated identically to ListPositions.
func (s *Store) ListPositionsWithHolder(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]PositionWithHolder, int, error) {
	page, pageSize = clampPage(page, pageSize)
	q := New(s.pool)

	total, err := q.CountPositions(ctx, pgFromUUID(companyID))
	if err != nil {
		return nil, 0, fmt.Errorf("org: count positions: %w", err)
	}
	todayDate, err := s.today(ctx, s.pool)
	if err != nil {
		return nil, 0, err
	}
	rows, err := q.ListPositionsWithHolder(ctx, ListPositionsWithHolderParams{
		CompanyID: pgFromUUID(companyID), Limit: int32(pageSize), Offset: int32((page - 1) * pageSize), Today: pgDate(todayDate),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("org: list positions with holder: %w", err)
	}
	out := make([]PositionWithHolder, 0, len(rows))
	for _, r := range rows {
		item := PositionWithHolder{Position: Position{
			ID: uuidFromPg(r.ID), CompanyID: uuidFromPg(r.CompanyID), Code: r.Code, Title: r.Title, OrgUnitID: uuidFromPg(r.OrgUnitID),
		}}
		if r.AssignmentID.Valid {
			id := uuidFromPg(r.AssignmentID)
			item.AssignmentID = &id
		}
		if r.AssignmentMemberID.Valid {
			id := uuidFromPg(r.AssignmentMemberID)
			item.AssignmentMemberID = &id
		}
		item.HolderDisplayName = r.HolderDisplayName
		out = append(out, item)
	}
	return out, int(total), nil
}

// UpdatePosition updates title/org_unit_id. company_id/code are immutable after creation
// (UNIQUE(company_id, code) is the identity of the slot).
func (s *Store) UpdatePosition(ctx context.Context, actor string, id uuid.UUID, title string, orgUnitID uuid.UUID) (Position, error) {
	title = strings.TrimSpace(title)
	if err := validateNameLen("title", title, 1, 120); err != nil {
		return Position{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Position{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// Lock before the snapshot-dependent checks below (see UpdateOrgUnit).
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return Position{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}

	q := New(s.pool).WithTx(tx)

	// org_unit_id is the only company-relevant field UpdatePosition can change
	// (company_id itself is immutable per this method's own doc comment) — fetch the position's
	// existing company_id to validate the new org_unit_id sits beneath it.
	existing, err := q.GetPosition(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Position{}, ErrPositionNotFound
		}
		return Position{}, fmt.Errorf("org: get position: %w", err)
	}
	under, err := s.orgUnitUnderCompany(ctx, tx, orgUnitID, uuidFromPg(existing.CompanyID))
	if err != nil {
		return Position{}, err
	}
	if !under {
		return Position{}, &ValidationError{Field: "orgUnitId", Message: "org unit must sit beneath the position's companyId in the org_unit tree"}
	}

	row, err := q.UpdatePosition(ctx, UpdatePositionParams{ID: pgFromUUID(id), Title: title, OrgUnitID: pgFromUUID(orgUnitID)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Position{}, ErrPositionNotFound
		}
		return Position{}, classifyPgError(err)
	}
	position := positionFromRow(row)
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.position.update", Subject: "position:" + id.String(), Payload: positionFields(position),
	}); err != nil {
		return Position{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Position{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return position, nil
}

// DeletePosition deletes a position. The FK from position_assignment (no ON DELETE CASCADE) is
// the storage-level guard against deleting a position with assignment history — it surfaces as
// a foreign_key_violation, classified to a 409 ReferencedError. A second guard runs inside the
// same transaction, after locking the position row FOR UPDATE (so a concurrent assignment
// insert, which takes FOR KEY SHARE on the row through its FK, serialises against the delete):
// refuse (PositionBoundError, 409) while any tuple still names `position:<id>#holder` as
// SUBJECT — i.e. some module (e.g. helpdesk) still binds an access tier to this position. Never
// cascade-revokes the other module's grant to unblock itself.
// Known ceiling: a module bind racing the delete (authz.tuple insert, no FK to org.position) can
// still land after the count; org's tree lock does not cover authz writes — a cross-service
// lock would be the upgrade if that race is ever observed.
func (s *Store) DeletePosition(ctx context.Context, actor string, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	var companyID pgtype.UUID
	if err := tx.QueryRow(ctx, `SELECT company_id FROM org.position WHERE id = $1 FOR UPDATE`, pgFromUUID(id)).Scan(&companyID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPositionNotFound
		}
		return fmt.Errorf("org: read position company: %w", err)
	}
	var boundCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE subject_type = 'position' AND subject_id = $1 AND subject_relation = 'holder'
	`, id.String()).Scan(&boundCount); err != nil {
		return fmt.Errorf("org: check position holder bindings: %w", err)
	}
	if boundCount > 0 {
		return &PositionBoundError{Count: boundCount}
	}
	// Revoke the position's company anchor in the same transaction as the row delete (via the
	// SECURITY DEFINER seam — migrations/authz/0009 admits the `position#company` shape).
	if err := authzstore.RevokePositionOrMemberTuple(ctx, tx, actor, "", orgObjectCompanyTuple("position", id, uuidFromPg(companyID))); err != nil {
		return fmt.Errorf("org: revoke position company tuple: %w", err)
	}
	affected, err := q.DeletePosition(ctx, pgFromUUID(id))
	if err != nil {
		return classifyDeleteError(err)
	}
	if affected == 0 {
		return ErrPositionNotFound
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.position.delete", Subject: "position:" + id.String(),
	}); err != nil {
		return fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("org: commit tx: %w", err)
	}
	return nil
}

// CompanyFacts is the company-typed org_unit state, plus its optional membership fact for one
// kcSub — the two read shapes authz's decision.CompanySource/MembershipSource wire to.
// Both are separate queries below (a company-state check and a membership check are independent
// questions with independent HTTP endpoints), grouped here only as a doc anchor.

// CompanyState reports whether id resolves to a COMPANY-typed org_unit and, if so, its
// is_active flag (`GET /internal/org/companies/{id}/state`, authz's decision.CompanySource
// step 5). A non-company-typed org_unit or an unknown id both report exists=false — never a
// fabricated company for the wrong type of unit.
func (s *Store) CompanyState(ctx context.Context, id uuid.UUID) (exists bool, isActive bool, err error) {
	q := New(s.pool)
	row, err := q.GetCompanyState(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("org: company state: %w", err)
	}
	return true, row.IsActive, nil
}

// MemberByCompanyAndKcSub resolves the member (if any) linking kcSub within companyID
// (`GET /internal/org/companies/{id}/members/by-kcsub/{kcSub}`, authz's decision.MembershipSource
// step 5) — joined via the published identity.user_read_v view, same read path
// ListMembers/GetMemberWithUser already use. No row (unknown kcSub, or a member in a different
// company) reports isMember=false — never a fabricated membership.
func (s *Store) MemberByCompanyAndKcSub(ctx context.Context, companyID uuid.UUID, kcSub string) (isMember bool, memberID uuid.UUID, isActive bool, err error) {
	q := New(s.pool)
	row, err := q.GetMemberByCompanyAndKcSub(ctx, GetMemberByCompanyAndKcSubParams{CompanyID: pgFromUUID(companyID), KcSub: kcSub})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, uuid.UUID{}, false, nil
		}
		return false, uuid.UUID{}, false, fmt.Errorf("org: member by kcsub: %w", err)
	}
	return true, uuidFromPg(row.ID), row.IsActive, nil
}

// CompanySummary is one company row in ListActiveCompaniesForKcSub's result — the fields the
// company-switcher needs, nothing more.
type CompanySummary struct {
	ID       uuid.UUID
	Code     string
	Name     string
	IsActive bool
}

// ListActiveCompaniesForKcSub returns the companies where kcSub has an active membership in an
// active company (`GET /internal/org/me/companies`, the company-switcher source) — one SQL
// query, filtered/sorted in SQL. An unknown kcSub (no linked user, or a
// user with no active memberships) returns an empty slice, never an error.
func (s *Store) ListActiveCompaniesForKcSub(ctx context.Context, kcSub string) ([]CompanySummary, error) {
	q := New(s.pool)
	rows, err := q.ListActiveCompaniesForKcSub(ctx, kcSub)
	if err != nil {
		return nil, fmt.Errorf("org: list active companies for kcsub: %w", err)
	}
	out := make([]CompanySummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, CompanySummary{ID: uuidFromPg(r.ID), Code: r.Code, Name: r.Name, IsActive: r.IsActive})
	}
	return out, nil
}

// MemberDirectoryEntry is the REDUCED member-directory view (least disclosure — no kcSub, no code, no lifecycle; modules resolve kcSubs server-side via the
// existing internal member-by-id read when they actually need one).
type MemberDirectoryEntry struct {
	ID            uuid.UUID
	DisplayName   string
	Email         string
	HasLinkedUser bool
}

// MemberDirectory returns companyID's ACTIVE member directory (the share-with/assign-to picker
// modules such as docs and helpdesk need), optionally filtered by a substring
// q (case-insensitive LITERAL substring, matched against displayName OR email, parameterized
// ILIKE with its wildcards escaped — never string-concatenated into SQL). page/pageSize follow
// the same 1/25, clamp 1..100 convention as ListMembers.
func (s *Store) MemberDirectory(ctx context.Context, companyID uuid.UUID, q string, page, pageSize int) ([]MemberDirectoryEntry, int, error) {
	page, pageSize = clampPage(page, pageSize)
	query := New(s.pool)

	var qParam *string
	if q != "" {
		escaped := likeEscaper.Replace(q)
		qParam = &escaped
	}

	total, err := query.CountMemberDirectory(ctx, CountMemberDirectoryParams{CompanyID: pgFromUUID(companyID), Q: qParam})
	if err != nil {
		return nil, 0, fmt.Errorf("org: count member directory: %w", err)
	}
	rows, err := query.ListMemberDirectory(ctx, ListMemberDirectoryParams{
		CompanyID: pgFromUUID(companyID), Limit: int32(pageSize), Offset: int32((page - 1) * pageSize), Q: qParam,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("org: list member directory: %w", err)
	}
	out := make([]MemberDirectoryEntry, 0, len(rows))
	for _, r := range rows {
		email := ""
		if r.Email != nil {
			email = *r.Email
		}
		out = append(out, MemberDirectoryEntry{ID: uuidFromPg(r.ID), DisplayName: r.DisplayName, Email: email, HasLinkedUser: r.HasLinkedUser})
	}
	return out, int(total), nil
}

// likeEscaper makes a user string a literal ILIKE substring (the queries declare ESCAPE '\').
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// ErrCrossCompanyAssignment is the store-level VALIDATION_FAILED for an assignment
// whose member does not belong to the position's company.
var ErrCrossCompanyAssignment = &ValidationError{Field: "memberId", Message: "member must belong to the position's company"}

// AssignNow is the assign-NOW surface (`POST /internal/org/positions/{id}/assignments`):
// server sets valid_from = today (NO caller-supplied dates), grants
// `position:<id>#holder @ member:<memberId>#mapped_user` in the SAME transaction as the
// assignment row insert, and audits `org.assignment.create`. memberID must resolve to an ACTIVE
// member of positionID's own company.
func (s *Store) AssignNow(ctx context.Context, actor string, positionID, memberID uuid.UUID) (Assignment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assignment{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// Lock before the snapshot-dependent checks below.
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return Assignment{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}

	q := New(s.pool).WithTx(tx)

	memberRow, err := q.GetMember(ctx, pgFromUUID(memberID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Assignment{}, ErrMemberNotFound
		}
		return Assignment{}, fmt.Errorf("org: get member: %w", err)
	}
	member := memberFromRow(memberRow)
	if !member.IsActive {
		return Assignment{}, ErrMemberInactive
	}

	positionRow, err := q.GetPosition(ctx, pgFromUUID(positionID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Assignment{}, ErrPositionNotFound
		}
		return Assignment{}, fmt.Errorf("org: get position: %w", err)
	}
	position := positionFromRow(positionRow)
	if position.CompanyID != member.CompanyID {
		return Assignment{}, ErrCrossCompanyAssignment
	}

	validFrom, err := s.today(ctx, tx)
	if err != nil {
		return Assignment{}, err
	}
	asgRow, err := q.CreateAssignment(ctx, CreateAssignmentParams{
		PositionID: pgFromUUID(positionID), MemberID: pgFromUUID(memberID), ValidFrom: pgDate(validFrom), ValidTo: pgtype.Date{},
	})
	if err != nil {
		return Assignment{}, classifyPgError(err)
	}
	assignment := assignmentFromRow(asgRow)

	if err := authzstore.Grant(ctx, tx, actor, "", authzstore.Tuple{
		ObjectType: "position", ObjectID: positionID.String(), Relation: "holder",
		SubjectType: "member", SubjectID: memberID.String(), SubjectRelation: "mapped_user",
	}); err != nil {
		return Assignment{}, fmt.Errorf("org: grant position holder tuple: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.assignment.create", Subject: "assignment:" + assignment.ID.String(),
		Payload: map[string]any{
			"positionId": positionID.String(), "memberId": memberID.String(), "validFrom": validFrom.Format("2006-01-02"),
		},
	}); err != nil {
		return Assignment{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Assignment{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return assignment, nil
}

// EndAssignment closes an assignment's validity window as of TODAY (the end-NOW surface — NO
// caller-supplied validTo) — a fact update, not a workflow (no approval/state-machine semantics
// here). Revokes
// `position:<id>#holder @ member:<memberId>#mapped_user` and audits `org.assignment.end`, both in
// the SAME transaction as the state change.
func (s *Store) EndAssignment(ctx context.Context, actor string, id uuid.UUID) (Assignment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assignment{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	existingRow, err := q.GetAssignment(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Assignment{}, ErrAssignmentNotFound
		}
		return Assignment{}, fmt.Errorf("org: get assignment: %w", err)
	}
	existing := assignmentFromRow(existingRow)
	if existing.ValidTo != nil {
		return Assignment{}, ErrAssignmentAlreadyEnded
	}

	validTo, err := s.today(ctx, tx)
	if err != nil {
		return Assignment{}, err
	}
	if validTo.Before(existing.ValidFrom) {
		return Assignment{}, &ValidationError{Field: "validTo", Message: "cannot end an assignment before it starts"}
	}

	row, err := q.EndAssignment(ctx, EndAssignmentParams{ID: pgFromUUID(id), ValidTo: pgDate(validTo)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Assignment{}, ErrAssignmentNotFound
		}
		return Assignment{}, classifyPgError(err)
	}
	assignment := assignmentFromRow(row)

	// The holder tuple is one fact per (position, member) pair, not per assignment row: revoke it
	// only when no OTHER open assignment for the pair still confers it (same tx, same snapshot).
	otherOpen, err := q.CountOtherOpenAssignments(ctx, CountOtherOpenAssignmentsParams{
		ID: pgFromUUID(id), PositionID: row.PositionID, MemberID: row.MemberID,
	})
	if err != nil {
		return Assignment{}, fmt.Errorf("org: count other open assignments: %w", err)
	}
	if otherOpen == 0 {
		if err := authzstore.RevokePositionOrMemberTuple(ctx, tx, actor, "", authzstore.Tuple{
			ObjectType: "position", ObjectID: assignment.PositionID.String(), Relation: "holder",
			SubjectType: "member", SubjectID: assignment.MemberID.String(), SubjectRelation: "mapped_user",
		}); err != nil {
			return Assignment{}, fmt.Errorf("org: revoke position holder tuple: %w", err)
		}
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.assignment.end", Subject: "assignment:" + id.String(),
		Payload: map[string]any{
			"positionId": assignment.PositionID.String(), "memberId": assignment.MemberID.String(),
			"validFrom": assignment.ValidFrom.Format("2006-01-02"), "validTo": validTo.Format("2006-01-02"),
		},
	}); err != nil {
		return Assignment{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Assignment{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return assignment, nil
}

// AssignmentOnDate answers "who holds position P on date D".
func (s *Store) AssignmentOnDate(ctx context.Context, positionID uuid.UUID, date time.Time) (Assignment, error) {
	q := New(s.pool)
	row, err := q.GetAssignmentOnDate(ctx, GetAssignmentOnDateParams{PositionID: pgFromUUID(positionID), ValidFrom: pgDate(date)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Assignment{}, ErrAssignmentNotFound
		}
		return Assignment{}, fmt.Errorf("org: assignment on date: %w", err)
	}
	return assignmentFromRow(row), nil
}

// CreateAndAssign is the combined create+assign operation (POST
// /internal/org/positions:create-and-assign, one transaction — a usability shortcut for small
// orgs): creates the position and its first assignment atomically — a failure at the
// assign step (e.g. the member doesn't exist, or an overlap somehow) rolls back the position
// creation too, so no orphan position is left behind.
func (s *Store) CreateAndAssign(
	ctx context.Context, actor string,
	companyID uuid.UUID, code, title string, orgUnitID uuid.UUID,
	memberID uuid.UUID, validFrom time.Time, validTo *time.Time,
) (Position, Assignment, error) {
	code = normalizeCode(code)
	title = strings.TrimSpace(title)
	if err := validateCode("code", code); err != nil {
		return Position{}, Assignment{}, err
	}
	if err := validateNameLen("title", title, 1, 120); err != nil {
		return Position{}, Assignment{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Position{}, Assignment{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// create-and-assign keeps its caller-supplied-window shape, but a FUTURE-dated window is
	// rejected — nothing would grant the holder tuple on the future date (no scheduler/reconciler
	// exists).
	todayDate, err := s.today(ctx, tx)
	if err != nil {
		return Position{}, Assignment{}, err
	}
	if validFrom.After(todayDate) {
		return Position{}, Assignment{}, &ValidationError{Field: "validFrom", Message: "future-dated create-and-assign is not supported (v1)"}
	}

	// Lock before the snapshot-dependent checks below (see UpdateOrgUnit).
	if _, err := tx.Exec(ctx, `SELECT org.lock_org_tree()`); err != nil {
		return Position{}, Assignment{}, fmt.Errorf("org: acquire org tree lock: %w", err)
	}

	// Same two store-level checks as CreatePosition/AssignNow, ahead of
	// migration 0004's trigger backstop.
	under, err := s.orgUnitUnderCompany(ctx, tx, orgUnitID, companyID)
	if err != nil {
		return Position{}, Assignment{}, err
	}
	if !under {
		return Position{}, Assignment{}, &ValidationError{Field: "orgUnitId", Message: "org unit must sit beneath companyId in the org_unit tree"}
	}
	if memberCompany, found, err := s.memberCompanyID(ctx, tx, memberID); err != nil {
		return Position{}, Assignment{}, err
	} else if found && memberCompany != companyID {
		return Position{}, Assignment{}, ErrCrossCompanyAssignment
	}

	q := New(s.pool).WithTx(tx)
	posRow, err := q.CreatePosition(ctx, CreatePositionParams{CompanyID: pgFromUUID(companyID), Code: code, Title: title, OrgUnitID: pgFromUUID(orgUnitID)})
	if err != nil {
		return Position{}, Assignment{}, classifyPgError(err)
	}
	position := positionFromRow(posRow)

	asgRow, err := q.CreateAssignment(ctx, CreateAssignmentParams{
		PositionID: posRow.ID, MemberID: pgFromUUID(memberID), ValidFrom: pgDate(validFrom), ValidTo: pgDatePtr(validTo),
	})
	if err != nil {
		// tx.Rollback via defer undoes the position insert above — the whole point of the
		// combined op being one transaction.
		return Position{}, Assignment{}, classifyPgError(err)
	}
	assignment := assignmentFromRow(asgRow)

	// Grant the position-holder tuple ONLY when this window actually covers today
	// (half-open: validFrom <= today < validTo, or validTo unset). A wholly past/closed window
	// (historical data entry) creates the fact row but confers no CURRENT access.
	if !validFrom.After(todayDate) && (validTo == nil || validTo.After(todayDate)) {
		if err := authzstore.Grant(ctx, tx, actor, "", authzstore.Tuple{
			ObjectType: "position", ObjectID: position.ID.String(), Relation: "holder",
			SubjectType: "member", SubjectID: memberID.String(), SubjectRelation: "mapped_user",
		}); err != nil {
			return Position{}, Assignment{}, fmt.Errorf("org: grant position holder tuple: %w", err)
		}
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.position.create_and_assign", Subject: "position:" + position.ID.String(),
		Payload: map[string]any{"positionCode": code, "memberId": memberID.String()},
	}); err != nil {
		return Position{}, Assignment{}, fmt.Errorf("org: audit mutation: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Position{}, Assignment{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return position, assignment, nil
}
