// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
)

// TestMember_CRUD proves basic member CRUD plus the directory read's identity join staying nil
// for an unlinked member.
func TestMember_CRUD(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "MEM1")
	member := mustCreateMember(t, store, company.ID, "M100")
	if member.UserID != nil {
		t.Fatalf("new member should have no user link, got %v", member.UserID)
	}

	got, err := store.GetMember(ctx, member.ID)
	if err != nil {
		t.Fatalf("get member: %v", err)
	}
	if got.Code != "M100" || got.UserKcSub != "" {
		t.Fatalf("unexpected member: %+v", got)
	}

	updated, err := store.UpdateMember(ctx, "tester", member.ID, "New Name", "new@example.com", false)
	if err != nil {
		t.Fatalf("update member: %v", err)
	}
	if updated.DisplayName != "New Name" || updated.Email != "new@example.com" || updated.IsActive {
		t.Fatalf("update not applied: %+v", updated)
	}

	members, total, err := store.ListMembers(ctx, company.ID, 1, 25)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if total != 1 || len(members) != 1 {
		t.Fatalf("expected 1 member, got total=%d len=%d", total, len(members))
	}
}

// TestMember_LinkUser_FakedHTTP proves link/unlink go through the IdentityStateChecker HTTP
// seam (faked here with httptest), never trusting the kcSub input
// directly, and that a linked member's directory read carries the joined identity fields.
func TestMember_LinkUser_FakedHTTP(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "MEM2")
	member := mustCreateMember(t, store, company.ID, "M200")
	mustCreateIdentityUser(t, admin, "kc-sub-link")

	fakeIdentity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/internal/identity/users/kc-sub-link/state" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"lifecycle": "active", "kcEnabled": "true"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "NOT_FOUND", "message": "not found"}})
	}))
	defer fakeIdentity.Close()

	checker := NewIdentityClient(fakeIdentity.Client(), fakeIdentity.URL)

	linked, err := store.LinkUser(ctx, "tester", checker, member.ID, "kc-sub-link")
	if err != nil {
		t.Fatalf("link user: %v", err)
	}
	if linked.UserID == nil {
		t.Fatal("expected member to be linked")
	}
	if linked.UserKcSub != "kc-sub-link" {
		t.Fatalf("expected directory read to carry the joined identity field, got %+v", linked)
	}

	// Linking a kcSub identity doesn't confirm (never trusting the input) is rejected.
	_, err = store.LinkUser(ctx, "tester", checker, member.ID, "kc-sub-ghost")
	if !errors.Is(err, ErrUserNotConfirmed) {
		t.Fatalf("expected ErrUserNotConfirmed for an unconfirmed kcSub, got %v", err)
	}

	unlinked, err := store.UnlinkUser(ctx, "tester", member.ID)
	if err != nil {
		t.Fatalf("unlink user: %v", err)
	}
	if unlinked.UserID != nil {
		t.Fatalf("expected member to be unlinked, got %v", unlinked.UserID)
	}
}

// TestMember_LinkUser_UnreachableIdentityFailsClosed proves an unreachable identity service
// never gets treated as "exists" — a transport error must reject the link, not silently allow
// it.
func TestMember_LinkUser_UnreachableIdentityFailsClosed(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "MEM3")
	member := mustCreateMember(t, store, company.ID, "M300")

	checker := NewIdentityClient(&http.Client{}, "http://127.0.0.1:1") // nothing listens here

	_, err := store.LinkUser(ctx, "tester", checker, member.ID, "kc-sub-unreachable")
	if !errors.Is(err, ErrUserNotConfirmed) {
		t.Fatalf("expected ErrUserNotConfirmed (fail-closed) when identity is unreachable, got %v", err)
	}
}

// TestMember_PIIAudit_FullFieldSet proves a member mutation audits the FULL
// before/after field set (not just the changed field), including email — the only PII field v1.
func TestMember_PIIAudit_FullFieldSet(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "MEM4")
	member, err := store.CreateMember(ctx, "actor-1", company.ID, "M400", "Original Name", "orig@example.com", true)
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	if _, err := store.UpdateMember(ctx, "actor-2", member.ID, "Changed Name", "changed@example.com", false); err != nil {
		t.Fatalf("update member: %v", err)
	}

	var payload []byte
	err = admin.QueryRow(ctx, `
		SELECT payload FROM audit.org__events
		WHERE action = 'org.member.update' AND subject = $1
		ORDER BY id DESC LIMIT 1
	`, "member:"+member.ID.String()).Scan(&payload)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}

	var body struct {
		Before map[string]any `json:"before"`
		After  map[string]any `json:"after"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}

	for _, field := range []string{"code", "displayName", "email", "userId", "isActive"} {
		if _, ok := body.Before[field]; !ok {
			t.Errorf("audit 'before' missing field %q: %v", field, body.Before)
		}
		if _, ok := body.After[field]; !ok {
			t.Errorf("audit 'after' missing field %q: %v", field, body.After)
		}
	}
	if body.Before["email"] != "orig@example.com" || body.After["email"] != "changed@example.com" {
		t.Fatalf("email not captured correctly: before=%v after=%v", body.Before["email"], body.After["email"])
	}
	if body.Before["displayName"] == body.After["displayName"] {
		t.Fatalf("displayName should differ between before/after: %v", body.Before)
	}
}

// TestMember_AuditAtomicWithMutation proves the audit row commits in the SAME transaction as
// the state change: a bogus audit table name (forcing Record to fail) must roll back
// the member mutation too.
func TestMember_AuditAtomicWithMutation(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	pool := orgPool(t)
	ctx := context.Background()

	badWriter, err := audit.NewWriter("audit.org__nonexistent")
	if err != nil {
		t.Fatalf("build bad audit writer (name still matches the convention, table just doesn't exist): %v", err)
	}
	store := NewStore(pool, badWriter)

	// The fixture company must come from a WORKING store: CreateOrgUnit is
	// audit-atomic too, so the bad-writer store now (correctly) fails at this step as well —
	// the member mutation below is the one this test puts under the microscope.
	company := mustCreateCompany(t, newTestStore(t), "MEM5")
	_, err = store.CreateMember(ctx, "actor", company.ID, "M500", "Name", "e@example.com", true)
	if err == nil {
		t.Fatal("expected CreateMember to fail when the audit write fails")
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.member WHERE company_id = $1`, company.ID).Scan(&count); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the member insert to roll back when its audit write failed, found %d row(s)", count)
	}
}
