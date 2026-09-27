// SPDX-License-Identifier: Apache-2.0

// Golden tests for org's key audit event PAYLOAD SHAPES (keys + JSON
// value types, never values — see internal/testauditgolden's doc comment). Covers
// org.position.create, org.assignment.create, org.group.create. Each test drives the REAL store
// method against the live test DB, then reads the actual persisted payload back out of
// audit.org__events.
package org

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testauditgolden"
)

// uniqueCode returns an org_unit/position/group code unique to this test RUN (not just this
// test): these tests commit real rows to the shared kiban-test database (no rollback — the
// audit row they read back must actually be committed), so a fixed literal code would collide
// with a previous run's leftover row (org_unit_root_code_unique etc. are permanent uniqueness
// constraints, not per-test-transaction scoped). Must satisfy validateCode's
// ^[A-Z0-9_-]{2,32}$ pattern.
func uniqueCode(prefix string) string {
	return prefix + strings.ToUpper(strings.ReplaceAll(uuid.New().String()[:8], "-", ""))
}

func fetchOrgAuditPayload(t *testing.T, store *Store, subject, action string) []byte {
	t.Helper()
	var payload []byte
	err := store.pool.QueryRow(context.Background(), `
		SELECT payload FROM audit.org__events
		WHERE subject = $1 AND action = $2
		ORDER BY occurred_at DESC LIMIT 1`, subject, action).Scan(&payload)
	if err != nil {
		t.Fatalf("fetch audit payload for subject=%s action=%s: %v", subject, action, err)
	}
	return payload
}

func assertOrgGoldenShape(t *testing.T, name string, payload []byte) {
	t.Helper()
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_"+name+".txt"), shape)
}

func TestAuditGolden_PositionCreate(t *testing.T) {
	store := newTestStore(t)
	company := mustCreateCompany(t, store, uniqueCode("AGP"))
	p := mustCreatePosition(t, store, company.ID, company.ID, uniqueCode("AGPP"))
	payload := fetchOrgAuditPayload(t, store, "position:"+p.ID.String(), "org.position.create")
	assertOrgGoldenShape(t, "position_create", payload)
}

func TestAuditGolden_AssignmentCreate(t *testing.T) {
	store := newTestStore(t)
	company := mustCreateCompany(t, store, uniqueCode("AGA"))
	p := mustCreatePosition(t, store, company.ID, company.ID, uniqueCode("AGAP"))
	m := mustCreateMember(t, store, company.ID, uniqueCode("AGAM"))
	assignment, err := store.AssignNow(context.Background(), "test-actor", p.ID, m.ID)
	if err != nil {
		t.Fatalf("AssignNow: %v", err)
	}
	payload := fetchOrgAuditPayload(t, store, "assignment:"+assignment.ID.String(), "org.assignment.create")
	assertOrgGoldenShape(t, "assignment_create", payload)
}

func TestAuditGolden_GroupCreate(t *testing.T) {
	store := newTestStore(t)
	company := mustCreateCompany(t, store, uniqueCode("AGG"))
	g, err := store.CreateGroup(context.Background(), "test-actor", company.ID, uniqueCode("AGGG"), "Test Group")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	payload := fetchOrgAuditPayload(t, store, "group:"+g.ID.String(), "org.group.create")
	assertOrgGoldenShape(t, "group_create", payload)
}
