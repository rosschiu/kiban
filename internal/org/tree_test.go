// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
)

// TestTree_SubtreeFourLevels proves the recursive-CTE subtree query is correct on a 4-level
// tree: company -> territory -> business_unit -> business_unit, plus a sibling branch that must
// NOT appear in the subtree of a different node.
func TestTree_SubtreeFourLevels(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "TREE1")
	territoryA := mustCreateUnit(t, store, "territory", company.ID, "TERR-A")
	territoryB := mustCreateUnit(t, store, "territory", company.ID, "TERR-B")
	buA1 := mustCreateUnit(t, store, "business_unit", territoryA.ID, "BU-A1")
	buA1a := mustCreateUnit(t, store, "business_unit", buA1.ID, "BU-A1A")

	subtree, err := store.Subtree(ctx, company.ID)
	if err != nil {
		t.Fatalf("subtree(company): %v", err)
	}
	ids := map[string]int{}
	for _, u := range subtree {
		ids[u.Code] = u.Depth
	}
	wantDepth := map[string]int{
		"TREE1": 0, "TERR-A": 1, "TERR-B": 1, "BU-A1": 2, "BU-A1A": 3,
	}
	for code, depth := range wantDepth {
		got, ok := ids[code]
		if !ok {
			t.Fatalf("subtree(company) missing %s; got %v", code, ids)
		}
		if got != depth {
			t.Errorf("depth(%s) = %d, want %d", code, got, depth)
		}
	}
	if len(subtree) != len(wantDepth) {
		t.Fatalf("subtree(company) has %d nodes, want %d: %v", len(subtree), len(wantDepth), ids)
	}

	// Subtree rooted at territoryB must contain ONLY territoryB (no siblings, no cousins).
	subB, err := store.Subtree(ctx, territoryB.ID)
	if err != nil {
		t.Fatalf("subtree(territoryB): %v", err)
	}
	if len(subB) != 1 || subB[0].Code != "TERR-B" {
		t.Fatalf("subtree(territoryB) = %v, want exactly [TERR-B]", subB)
	}

	// Depth-3 node's own subtree is just itself (leaf).
	subLeaf, err := store.Subtree(ctx, buA1a.ID)
	if err != nil {
		t.Fatalf("subtree(buA1a): %v", err)
	}
	if len(subLeaf) != 1 {
		t.Fatalf("subtree(leaf) = %v, want exactly 1 node", subLeaf)
	}
}

// TestTree_MoveSubtreeCycleRejected proves the cycle-proof parent-change validation: moving an
// ancestor under its own descendant must be rejected, while a legitimate move (to an unrelated
// branch) succeeds.
func TestTree_MoveSubtreeCycleRejected(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "TREE2")
	territoryA := mustCreateUnit(t, store, "territory", company.ID, "TERR-A")
	buA1 := mustCreateUnit(t, store, "business_unit", territoryA.ID, "BU-A1")
	territoryB := mustCreateUnit(t, store, "territory", company.ID, "TERR-B")

	// Cycle: move territoryA under its own descendant buA1.
	_, err := store.UpdateOrgUnit(ctx, "test-actor", territoryA.ID, &buA1.ID, territoryA.Code, territoryA.Name, true)
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError moving a unit under its own descendant, got %v", err)
	}
	if vErr.Field != "parentId" {
		t.Fatalf("expected field=parentId, got %q", vErr.Field)
	}

	// Self-parent is also rejected.
	_, err = store.UpdateOrgUnit(ctx, "test-actor", territoryA.ID, &territoryA.ID, territoryA.Code, territoryA.Name, true)
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError moving a unit under itself, got %v", err)
	}

	// Legitimate move: buA1 moves from territoryA to territoryB (no cycle).
	moved, err := store.UpdateOrgUnit(ctx, "test-actor", buA1.ID, &territoryB.ID, buA1.Code, buA1.Name, true)
	if err != nil {
		t.Fatalf("expected legitimate move to succeed, got %v", err)
	}
	if moved.ParentID == nil || *moved.ParentID != territoryB.ID {
		t.Fatalf("buA1 not moved: parentId = %v, want %s", moved.ParentID, territoryB.ID)
	}

	subB, err := store.Subtree(ctx, territoryB.ID)
	if err != nil {
		t.Fatalf("subtree(territoryB): %v", err)
	}
	if len(subB) != 2 {
		t.Fatalf("subtree(territoryB) after move = %v, want 2 nodes", subB)
	}
}

// TestTree_DeleteGuards proves org-unit CRUD's delete guards: cannot delete a unit with
// children, cannot delete a company with members; deleting a genuinely empty leaf succeeds.
func TestTree_DeleteGuards(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "TREE3")
	territory := mustCreateUnit(t, store, "territory", company.ID, "TERR")

	if err := store.DeleteOrgUnit(ctx, "test-actor", company.ID); !errors.Is(err, ErrOrgUnitHasChildren) {
		t.Fatalf("expected ErrOrgUnitHasChildren deleting a unit with a child, got %v", err)
	}

	mustCreateMember(t, store, company.ID, "MM1")
	if err := store.DeleteOrgUnit(ctx, "test-actor", territory.ID); err != nil {
		t.Fatalf("expected deleting the childless, memberless territory to succeed, got %v", err)
	}

	if err := store.DeleteOrgUnit(ctx, "test-actor", company.ID); !errors.Is(err, ErrOrgUnitHasMembers) {
		t.Fatalf("expected ErrOrgUnitHasMembers deleting a company with a member, got %v", err)
	}
}
