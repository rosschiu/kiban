// SPDX-License-Identifier: Apache-2.0

// Store-level coverage for org.group/org.group_member — CRUD, the transactional
// tuple grant/revoke, and the single-writer invariant itself. The invariant's MUST-FAIL case
// comes right after basic CRUD, before any successful membership write.
package org

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustCreateGroup creates a Kiban-native group in companyID with a unique code.
func mustCreateGroup(t *testing.T, store *Store, companyID uuid.UUID, code string) Group {
	t.Helper()
	g, err := store.CreateGroup(context.Background(), "test-actor", companyID, code, "Test Group "+code)
	if err != nil {
		t.Fatalf("create group %s: %v", code, err)
	}
	return g
}

// mustCreateExternalGroup inserts a group row DIRECTLY (bypassing Store.CreateGroup, which can
// only ever create source='kiban' groups; only an external directory sync creates a non-'kiban'
// group in production) so this file's invariant tests have a fixture to exercise against.
func mustCreateExternalGroup(t *testing.T, admin *pgxpool.Pool, companyID uuid.UUID, code, source, externalRef string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := admin.QueryRow(context.Background(), `
		INSERT INTO org.group (company_id, code, name, source, external_ref)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		companyID, code, "External Group "+code, source, externalRef,
	).Scan(&id); err != nil {
		t.Fatalf("insert external group %s: %v", code, err)
	}
	return id
}

// TestGroup_CRUD proves basic group CRUD (mirrors TestPosition_CRUD's shape).
func TestGroup_CRUD(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "GRP1")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")

	if group.Source != "kiban" {
		t.Fatalf("Source = %q, want kiban (the default)", group.Source)
	}
	if group.ExternalRef != nil {
		t.Fatalf("ExternalRef = %v, want nil for a kiban-native group", group.ExternalRef)
	}
	if !group.IsKibanManaged() {
		t.Fatal("expected IsKibanManaged() true for a source='kiban' group")
	}

	got, err := store.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if got.Name != "Test Group SUPPORT" {
		t.Fatalf("unexpected group: %+v", got)
	}

	groups, total, err := store.ListGroupsWithMemberCount(ctx, company.ID, 1, 25)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected 1 group, got total=%d len=%d", total, len(groups))
	}
	if groups[0].MemberCount != 0 {
		t.Fatalf("expected 0 members on a freshly created group, got %d", groups[0].MemberCount)
	}
}

// TestGroup_AddMember_ExternallySourced_MustFail proves the single-writer invariant's own MUST
// FAIL case: membership writes on any group whose source != 'kiban' are
// refused with ErrGroupExternallyManaged (409 GROUP_EXTERNALLY_MANAGED at the HTTP layer),
// through the STORE — the same wall every human/API path hits, no matter which handler calls it.
func TestGroup_AddMember_ExternallySourced_MustFail(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "GRP2")
	member := mustCreateMember(t, store, company.ID, "GRP2-MEM")
	externalGroupID := mustCreateExternalGroup(t, admin, company.ID, "AD-ENG", "entra:contoso", "grp-ad-eng-001")

	_, err := store.AddGroupMember(ctx, "test-actor", externalGroupID, member.ID)
	if !errors.Is(err, ErrGroupExternallyManaged) {
		t.Fatalf("AddGroupMember on an externally-sourced group: got %v, want ErrGroupExternallyManaged", err)
	}

	// The refusal must be a true no-op: no group_member row, no tuple.
	var memberCount, tupleCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.group_member WHERE group_id=$1`, externalGroupID).Scan(&memberCount); err != nil {
		t.Fatalf("count group_member: %v", err)
	}
	if memberCount != 0 {
		t.Fatalf("group_member count = %d, want 0 (refused write must not touch the table)", memberCount)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple WHERE object_type='group' AND object_id=$1`, externalGroupID.String(),
	).Scan(&tupleCount); err != nil {
		t.Fatalf("count tuple: %v", err)
	}
	if tupleCount != 0 {
		t.Fatalf("tuple count = %d, want 0 (refused write must not grant)", tupleCount)
	}
}

// TestGroup_RemoveMember_ExternallySourced_MustFail is the invariant's revocation-path mirror.
func TestGroup_RemoveMember_ExternallySourced_MustFail(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "GRP3")
	member := mustCreateMember(t, store, company.ID, "GRP3-MEM")
	externalGroupID := mustCreateExternalGroup(t, admin, company.ID, "AD-SALES", "entra:contoso", "grp-ad-sales-001")

	err := store.RemoveGroupMember(ctx, "test-actor", externalGroupID, member.ID)
	if !errors.Is(err, ErrGroupExternallyManaged) {
		t.Fatalf("RemoveGroupMember on an externally-sourced group: got %v, want ErrGroupExternallyManaged", err)
	}
}

// TestGroup_AddRemoveMember_KibanManaged_GrantsAndRevokesTuple proves the happy path a
// 'kiban'-sourced group takes: AddGroupMember grants group:<id>#member @
// member:<id>#mapped_user transactionally with the group_member row; RemoveGroupMember revokes
// it via the SECURITY DEFINER function (migrations/authz/0007's widened allow-list).
func TestGroup_AddRemoveMember_KibanManaged_GrantsAndRevokesTuple(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "GRP4")
	group := mustCreateGroup(t, store, company.ID, "SUPPORT")
	alice := mustCreateMember(t, store, company.ID, "GRP4-ALICE")
	bob := mustCreateMember(t, store, company.ID, "GRP4-BOB")

	if _, err := store.AddGroupMember(ctx, "test-actor", group.ID, alice.ID); err != nil {
		t.Fatalf("add alice: %v", err)
	}
	if _, err := store.AddGroupMember(ctx, "test-actor", group.ID, bob.ID); err != nil {
		t.Fatalf("add bob: %v", err)
	}

	tupleCount := func(memberID uuid.UUID) int {
		var c int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM authz.tuple
			WHERE object_type='group' AND object_id=$1 AND relation='member'
			  AND subject_type='member' AND subject_id=$2 AND subject_relation='mapped_user'`,
			group.ID.String(), memberID.String(),
		).Scan(&c); err != nil {
			t.Fatalf("count tuple: %v", err)
		}
		return c
	}
	if tupleCount(alice.ID) != 1 || tupleCount(bob.ID) != 1 {
		t.Fatalf("expected both alice and bob to have a group member tuple: alice=%d bob=%d", tupleCount(alice.ID), tupleCount(bob.ID))
	}

	members, err := store.ListGroupMembers(ctx, group.ID)
	if err != nil {
		t.Fatalf("list group members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}

	// Groups hold multiple members simultaneously (unlike position#holder) — removing bob must
	// leave alice's tuple standing.
	if err := store.RemoveGroupMember(ctx, "test-actor", group.ID, bob.ID); err != nil {
		t.Fatalf("remove bob: %v", err)
	}
	if tupleCount(bob.ID) != 0 {
		t.Fatal("expected bob's tuple revoked after removal")
	}
	if tupleCount(alice.ID) != 1 {
		t.Fatal("expected alice's tuple to survive bob's removal")
	}

	var auditActions []string
	rows, err := admin.Query(ctx, `SELECT action FROM audit.org__events WHERE subject=$1 ORDER BY id`, "group:"+group.ID.String())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		auditActions = append(auditActions, a)
	}
	wantActions := map[string]bool{"org.group.create": false, "org.group.member_add": false, "org.group.member_remove": false}
	for _, a := range auditActions {
		if _, ok := wantActions[a]; ok {
			wantActions[a] = true
		}
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("expected an audit row for %q, audit actions were: %v", action, auditActions)
		}
	}
}

// TestGroup_AddMember_CrossCompany_Rejected proves the same-company member trigger's store-level
// backstop check (mirrors ErrCrossCompanyAssignment's use in AssignNow).
func TestGroup_AddMember_CrossCompany_Rejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "GRP5A")
	companyB := mustCreateCompany(t, store, "GRP5B")
	group := mustCreateGroup(t, store, companyA.ID, "TEAM")
	outsider := mustCreateMember(t, store, companyB.ID, "OUTSIDER")

	_, err := store.AddGroupMember(ctx, "test-actor", group.ID, outsider.ID)
	if !errors.Is(err, ErrCrossCompanyAssignment) {
		t.Fatalf("AddGroupMember across companies: got %v, want ErrCrossCompanyAssignment", err)
	}
}

// TestGroup_AddMember_InactiveMember_Rejected proves inactive members can't be added (mirrors
// TestPositionHolder_AssignNow_InactiveMemberRejected).
func TestGroup_AddMember_InactiveMember_Rejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "GRP6")
	group := mustCreateGroup(t, store, company.ID, "TEAM")
	inactive, err := store.CreateMember(ctx, "test-actor", company.ID, "GRP6-MEM", "Inactive Member", "", false)
	if err != nil {
		t.Fatalf("create inactive member: %v", err)
	}

	_, err = store.AddGroupMember(ctx, "test-actor", group.ID, inactive.ID)
	var vErr *ValidationError
	if !errors.As(err, &vErr) || vErr.Field != "memberId" {
		t.Fatalf("expected ErrMemberInactive-shaped ValidationError, got %v", err)
	}
}
