// SPDX-License-Identifier: Apache-2.0

// org.group / org.group_member — the third org fact type (member · position · group),
// source-aware. A group is a company-scoped named set of members with exactly one authoritative
// source: `source='kiban'` groups are writable through this file's own membership methods (the
// human/API path); any other source is a group an external sync writer owns — its membership is
// READ-ONLY through every path this file exposes,
// enforced HERE in the store (never only at the HTTP layer), never by a second writer racing the
// first. Kept in its own file (store.go is already large) — same package, same Store receiver.
package org

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/audit"
	authzstore "github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/pgconv"
)

// Group is the API-facing shape of an org.group row.
type Group struct {
	ID          uuid.UUID
	CompanyID   uuid.UUID
	Code        string
	Name        string
	Source      string
	ExternalRef *string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsKibanManaged reports whether this group's membership is writable through the ordinary
// human/API surface — true only for source == "kiban" (the DEFAULT, and currently the ONLY
// source any group can actually have, since no sync writer exists yet).
func (g Group) IsKibanManaged() bool { return g.Source == "kiban" }

func groupFromRow(r OrgGroup) Group {
	return Group{
		ID: uuidFromPg(r.ID), CompanyID: uuidFromPg(r.CompanyID), Code: r.Code, Name: r.Name,
		Source: r.Source, ExternalRef: r.ExternalRef, IsActive: r.IsActive,
		CreatedAt: r.CreatedAt.Time, UpdatedAt: r.UpdatedAt.Time,
	}
}

// GroupWithMemberCount is the admin-list shape: a group plus how many members it currently has, so the UI never needs a second round trip per row.
type GroupWithMemberCount struct {
	Group
	MemberCount int
}

// GroupMember is the API-facing shape of one org.group_member row, joined with the member's own
// display fields (the shape the admin surface and helpdesk's assignable-groups read both need).
type GroupMember struct {
	GroupID           uuid.UUID
	MemberID          uuid.UUID
	AddedBy           string
	AddedAt           time.Time
	MemberDisplayName string
	MemberEmail       *string
}

var (
	// ErrGroupNotFound is returned when a group id doesn't resolve to any row.
	ErrGroupNotFound = errors.New("org: group not found")
	// ErrGroupMemberNotFound is the 404 for removing a member who is not in the group — no
	// audit row, no revoke (nothing changed).
	ErrGroupMemberNotFound = errors.New("org: member is not in this group")
	// ErrGroupExternallyManaged is the single-writer invariant's own sentinel (409
	// GROUP_EXTERNALLY_MANAGED): a membership write was attempted against a group whose source is
	// not "kiban". With no sync-writer entrypoint, NO write path can ever succeed against such a
	// group — this is not a restriction the HTTP layer works around, it is enforced in the store,
	// unconditionally, for every caller.
	ErrGroupExternallyManaged = errors.New("org: group is externally managed — membership is read-only here")
)

// CreateGroup creates a Kiban-native group (source is ALWAYS "kiban", external_ref is ALWAYS nil
// on this path — the only path the human/API surface ever calls). A sync-writer entrypoint that
// creates externally-sourced groups would be a DIFFERENT method; none exists.
func (s *Store) CreateGroup(ctx context.Context, actor string, companyID uuid.UUID, code, name string) (Group, error) {
	code = normalizeCode(code)
	name = strings.TrimSpace(name)
	if err := validateCode("code", code); err != nil {
		return Group{}, err
	}
	if err := validateNameLen("name", name, 1, 120); err != nil {
		return Group{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Group{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)
	row, err := q.CreateGroup(ctx, CreateGroupParams{
		CompanyID: pgFromUUID(companyID), Code: code, Name: name, Source: "kiban", ExternalRef: nil,
	})
	if err != nil {
		return Group{}, classifyPgError(err)
	}
	group := groupFromRow(row)
	if err := authzstore.Grant(ctx, tx, actor, "", orgObjectCompanyTuple("group", group.ID, companyID)); err != nil {
		return Group{}, fmt.Errorf("org: grant group company tuple: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.group.create", Subject: "group:" + group.ID.String(), Payload: groupFields(group),
	}); err != nil {
		return Group{}, fmt.Errorf("org: audit mutation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Group{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return group, nil
}

// GetGroup looks up a group by id.
func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	q := New(s.pool)
	row, err := q.GetGroup(ctx, pgFromUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, ErrGroupNotFound
		}
		return Group{}, fmt.Errorf("org: get group: %w", err)
	}
	return groupFromRow(row), nil
}

// ListGroupsWithMemberCount returns companyID's groups, paginated, each with its current member
// count.
func (s *Store) ListGroupsWithMemberCount(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]GroupWithMemberCount, int, error) {
	page, pageSize = clampPage(page, pageSize)
	q := New(s.pool)

	total, err := q.CountGroups(ctx, pgFromUUID(companyID))
	if err != nil {
		return nil, 0, fmt.Errorf("org: count groups: %w", err)
	}
	rows, err := q.ListGroupsWithMemberCount(ctx, ListGroupsWithMemberCountParams{
		CompanyID: pgFromUUID(companyID), Limit: int32(pageSize), Offset: int32((page - 1) * pageSize),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("org: list groups with member count: %w", err)
	}
	out := make([]GroupWithMemberCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, GroupWithMemberCount{
			Group: Group{
				ID: uuidFromPg(r.ID), CompanyID: uuidFromPg(r.CompanyID), Code: r.Code, Name: r.Name,
				Source: r.Source, ExternalRef: r.ExternalRef, IsActive: r.IsActive,
				CreatedAt: r.CreatedAt.Time, UpdatedAt: r.UpdatedAt.Time,
			},
			MemberCount: int(r.MemberCount),
		})
	}
	return out, int(total), nil
}

// ListGroupMembers returns groupID's current members, joined with display fields.
func (s *Store) ListGroupMembers(ctx context.Context, groupID uuid.UUID) ([]GroupMember, error) {
	q := New(s.pool)
	rows, err := q.ListGroupMembers(ctx, pgFromUUID(groupID))
	if err != nil {
		return nil, fmt.Errorf("org: list group members: %w", err)
	}
	out := make([]GroupMember, 0, len(rows))
	for _, r := range rows {
		out = append(out, GroupMember{
			GroupID: uuidFromPg(r.GroupID), MemberID: uuidFromPg(r.MemberID), AddedBy: r.AddedBy, AddedAt: r.AddedAt.Time,
			MemberDisplayName: r.MemberDisplayName, MemberEmail: r.MemberEmail,
		})
	}
	return out, nil
}

// AddGroupMember is the SOLE write path for Kiban-native group membership (the single-writer
// invariant). It:
//  1. resolves the group and REFUSES (ErrGroupExternallyManaged, 409) unless
//     group.IsKibanManaged() — enforced here, in the store, before any row is touched, so every
//     human/API caller hits the SAME wall no matter which handler reaches this method;
//  2. inserts the org.group_member row (the same-company trigger, migrations/org/0010, is the
//     DB-level backstop for the store-level check below);
//  3. grants `group:<id>#member @ member:<memberId>#mapped_user` in the SAME transaction;
//  4. audits `org.group.member_add`.
//
// memberID must resolve to an ACTIVE member of the group's own company (same posture as
// AssignNow's memberID check).
func (s *Store) AddGroupMember(ctx context.Context, actor string, groupID, memberID uuid.UUID) (GroupMember, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return GroupMember{}, fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)

	groupRow, err := q.GetGroup(ctx, pgFromUUID(groupID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupMember{}, ErrGroupNotFound
		}
		return GroupMember{}, fmt.Errorf("org: get group: %w", err)
	}
	group := groupFromRow(groupRow)
	// The single-writer invariant: refuse BEFORE touching group_member at all, for every caller,
	// every time — not a handler-level check that a second entrypoint could bypass.
	if !group.IsKibanManaged() {
		return GroupMember{}, ErrGroupExternallyManaged
	}

	memberRow, err := q.GetMember(ctx, pgFromUUID(memberID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupMember{}, ErrMemberNotFound
		}
		return GroupMember{}, fmt.Errorf("org: get member: %w", err)
	}
	member := memberFromRow(memberRow)
	if !member.IsActive {
		return GroupMember{}, ErrMemberInactive
	}
	if member.CompanyID != group.CompanyID {
		return GroupMember{}, ErrCrossCompanyAssignment
	}

	// AddGroupMember's query is ON CONFLICT DO NOTHING — adding an already-current member is
	// idempotent (no error, no duplicate row, no audit row for a no-op) and the response carries
	// the STORED added_by/added_at, never a fabricated pair. The tuple grant is likewise
	// idempotent (authzstore.Grant's INSERT is itself ON CONFLICT DO NOTHING).
	inserted, err := q.AddGroupMember(ctx, AddGroupMemberParams{GroupID: pgFromUUID(groupID), MemberID: pgFromUUID(memberID), AddedBy: actor})
	if err != nil {
		return GroupMember{}, classifyPgError(err)
	}
	stored, err := q.GetGroupMember(ctx, GetGroupMemberParams{GroupID: pgFromUUID(groupID), MemberID: pgFromUUID(memberID)})
	if err != nil {
		return GroupMember{}, fmt.Errorf("org: read group member: %w", err)
	}

	if err := authzstore.Grant(ctx, tx, actor, "", authzstore.Tuple{
		ObjectType: "group", ObjectID: groupID.String(), Relation: "member",
		SubjectType: "member", SubjectID: memberID.String(), SubjectRelation: "mapped_user",
	}); err != nil {
		return GroupMember{}, fmt.Errorf("org: grant group member tuple: %w", err)
	}

	if inserted > 0 {
		if err := s.audit.Record(ctx, tx, audit.Event{
			Actor: actor, Action: "org.group.member_add", Subject: "group:" + groupID.String(),
			Payload: map[string]any{"groupId": groupID.String(), "memberId": memberID.String()},
		}); err != nil {
			return GroupMember{}, fmt.Errorf("org: audit mutation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return GroupMember{}, fmt.Errorf("org: commit tx: %w", err)
	}
	return GroupMember{
		GroupID: groupID, MemberID: memberID, AddedBy: stored.AddedBy, AddedAt: stored.AddedAt.Time,
		MemberDisplayName: member.DisplayName, MemberEmail: pgconv.StrOrNil(member.Email),
	}, nil
}

// RemoveGroupMember is the SOLE revocation path for Kiban-native group membership — the mirror
// of AddGroupMember. Same single-writer refusal, ahead of any row touch; revokes the
// group:*#member tuple via the SECURITY DEFINER function (migrations/authz/0007 widened its
// allow-list for exactly this shape) — never a raw DELETE from application code.
func (s *Store) RemoveGroupMember(ctx context.Context, actor string, groupID, memberID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("org: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	q := New(s.pool).WithTx(tx)

	groupRow, err := q.GetGroup(ctx, pgFromUUID(groupID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGroupNotFound
		}
		return fmt.Errorf("org: get group: %w", err)
	}
	group := groupFromRow(groupRow)
	if !group.IsKibanManaged() {
		return ErrGroupExternallyManaged
	}

	affected, err := q.RemoveGroupMember(ctx, RemoveGroupMemberParams{GroupID: pgFromUUID(groupID), MemberID: pgFromUUID(memberID)})
	if err != nil {
		return fmt.Errorf("org: remove group member: %w", err)
	}
	if affected == 0 {
		// Not a member: nothing changed, so no revoke and no audit row — 404.
		return ErrGroupMemberNotFound
	}

	if err := authzstore.RevokePositionOrMemberTuple(ctx, tx, actor, "", authzstore.Tuple{
		ObjectType: "group", ObjectID: groupID.String(), Relation: "member",
		SubjectType: "member", SubjectID: memberID.String(), SubjectRelation: "mapped_user",
	}); err != nil {
		return fmt.Errorf("org: revoke group member tuple: %w", err)
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "org.group.member_remove", Subject: "group:" + groupID.String(),
		Payload: map[string]any{"groupId": groupID.String(), "memberId": memberID.String()},
	}); err != nil {
		return fmt.Errorf("org: audit mutation: %w", err)
	}
	return tx.Commit(ctx)
}

func groupFields(g Group) map[string]any {
	fields := map[string]any{
		"code": g.Code, "name": g.Name, "source": g.Source, "isActive": g.IsActive,
	}
	if g.ExternalRef != nil {
		fields["externalRef"] = *g.ExternalRef
	}
	return fields
}
