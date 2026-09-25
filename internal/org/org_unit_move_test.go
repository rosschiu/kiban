// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"
)

// This file proves cross-company integrity survives org-unit MOVES. Migration
// 0004_cross_company_constraints.sql's triggers only fire on org.position /
// org.position_assignment writes, so on their own they do not stop re-parenting a subtree under
// ANOTHER company from dragging its positions across the company boundary.

// TestOrgUnitMove_BypassReplay proves both halves of the fix: UpdateOrgUnit's store-level check
// (migration-independent) rejects the move with a 422-shaped ValidationError, AND a
// direct-SQL write that skips the store entirely is rejected by migration
// 0005_org_unit_move_company_integrity.sql's trigger backstop.
func TestOrgUnitMove_BypassReplay(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "MVCOA")
	companyB := mustCreateCompany(t, store, "MVCOB")
	territory := mustCreateUnit(t, store, "territory", companyA.ID, "MVTERR")
	mustCreatePosition(t, store, companyA.ID, territory.ID, "MVPOS1")

	// Application path: UpdateOrgUnit must reject the move with a 422-shaped ValidationError.
	_, err := store.UpdateOrgUnit(ctx, "test-actor", territory.ID, &companyB.ID, "MVTERR", "Moved Territory", true)
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ValidationError rejecting the cross-company move (store-level check), got %v", err)
	}
	if vErr.Field != "parentId" {
		t.Fatalf("expected field=parentId, got %q", vErr.Field)
	}

	// Direct-SQL bypass: skip the store entirely and issue the
	// UPDATE straight against org.org_unit. Migration 0005's trigger is the backstop that must
	// still reject this even when the application-level check is bypassed.
	_, err = admin.Exec(ctx, `UPDATE org.org_unit SET parent_id = $1 WHERE id = $2`, companyB.ID, territory.ID)
	if err == nil {
		t.Fatal("expected migration 0005's org_unit_move_must_preserve_company trigger to reject a direct-SQL cross-company move of a subtree that still holds a position")
	}
}

// TestOrgUnitMove_SameCompanySucceeds proves a legitimate move — re-parenting a subtree within
// its OWN company, positions and all — is never blocked by the cross-company move checks.
func TestOrgUnitMove_SameCompanySucceeds(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	company := mustCreateCompany(t, store, "MVCOC")
	oldParent := mustCreateUnit(t, store, "territory", company.ID, "MVOLDP")
	newParent := mustCreateUnit(t, store, "territory", company.ID, "MVNEWP")
	unit := mustCreateUnit(t, store, "business_unit", oldParent.ID, "MVUNIT")
	mustCreatePosition(t, store, company.ID, unit.ID, "MVPOS2")

	if _, err := store.UpdateOrgUnit(ctx, "test-actor", unit.ID, &newParent.ID, "MVUNIT", "Moved Unit", true); err != nil {
		t.Fatalf("expected a same-company subtree move (with positions) to succeed, got %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.org_unit WHERE id = $1 AND parent_id = $2`, unit.ID, newParent.ID).Scan(&count); err != nil {
		t.Fatalf("verify move: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the unit to be re-parented under newParent, got count=%d", count)
	}
}

// TestOrgUnitMove_EmptySubtreeCrossCompanyAllowed proves a
// subtree that holds NO positions anywhere inside it may re-home across companies freely —
// positions are the blocker, never the org-unit shape alone.
func TestOrgUnitMove_EmptySubtreeCrossCompanyAllowed(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	companyA := mustCreateCompany(t, store, "MVCOD")
	companyB := mustCreateCompany(t, store, "MVCOE")
	territory := mustCreateUnit(t, store, "territory", companyA.ID, "MVEMPTY")

	if _, err := store.UpdateOrgUnit(ctx, "test-actor", territory.ID, &companyB.ID, "MVEMPTY", "Re-homed Territory", true); err != nil {
		t.Fatalf("expected a position-free subtree to move cross-company freely, got %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM org.org_unit WHERE id = $1 AND parent_id = $2`, territory.ID, companyB.ID).Scan(&count); err != nil {
		t.Fatalf("verify move: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the empty territory to be re-parented under companyB, got count=%d", count)
	}
}
