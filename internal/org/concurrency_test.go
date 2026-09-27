// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Two CONCURRENT org-structure writers, each validating against its own consistent MVCC
// snapshot, could jointly commit an inconsistent world. Both probes below are
// barrier-synchronized so the race is near-deterministic rather than merely probable. Without
// migration 0006's advisory-lock triggers and store.go's lock-then-check ordering both tests
// fail; with them, both pass every iteration (run with `-count=1`: these are stateful
// integration tests against a live, mutating database).

// startBarrier runs n functions concurrently, releasing all of them at (as close to) the same
// instant as Go's scheduler allows: each goroutine signals "ready", then every goroutine blocks
// until the last one signals, then all proceed together. This is what makes the race
// near-deterministic instead of merely possible.
func startBarrier(n int, fn func(i int) error) []error {
	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ready.Done()
			<-start
			errs[i] = fn(i)
		}(i)
	}
	ready.Wait()
	close(start)
	wg.Wait()
	return errs
}

// walkParentChain follows org_unit.parent_id from startID up to maxHops steps, returning the
// visited ids in order (startID first). If a cycle exists, startID (or any other visited node)
// will reappear before parent_id runs out — the caller checks for that; this helper itself just
// stops after maxHops so a genuine cycle can never hang the test.
func walkParentChain(t *testing.T, store *Store, startID uuid.UUID, maxHops int) []uuid.UUID {
	t.Helper()
	ctx := context.Background()
	visited := []uuid.UUID{startID}
	cur := startID
	for i := 0; i < maxHops; i++ {
		unit, err := store.GetOrgUnit(ctx, cur)
		if err != nil {
			t.Fatalf("walk parent chain: get org unit %s: %v", cur, err)
		}
		if unit.ParentID == nil {
			return visited
		}
		visited = append(visited, *unit.ParentID)
		cur = *unit.ParentID
	}
	return visited
}

// assertNoCycle fails the test if id appears more than once in a maxHops-bounded walk of its own
// parent chain starting from id itself.
func assertNoCycle(t *testing.T, store *Store, id uuid.UUID) {
	t.Helper()
	chain := walkParentChain(t, store, id, 32)
	seen := map[uuid.UUID]bool{}
	for _, v := range chain {
		if seen[v] {
			t.Fatalf("REGRESSION: parent chain from %s contains a cycle: %v", id, chain)
		}
		seen[v] = true
	}
}

// TestConcurrentOrgTree_UnitMoveVsPositionCreate races a unit move against a position create: a unit
// (with an EMPTY subtree — no positions yet) moves from company A to company B, concurrently
// with a NEW position being created under that same unit, declared as belonging to company A.
// Pre-fix: UpdateOrgUnit's subtreeHasPositions check (sees no positions yet) and CreatePosition's
// orgUnitUnderCompany check (sees the unit still under A) each read a consistent snapshot BEFORE
// the other transaction's write — both pass, both commit, and the result is
// a position whose declared company (A) differs from its org_unit's actual resolved
// root company (B). Post-fix: the advisory lock serializes the two writers, so whichever commits
// first invalidates the other's check — exactly one of the two operations must fail, and the
// invariant (every position's company_id equals its org_unit's resolved root) must hold for
// every surviving position afterward, every iteration.
func TestConcurrentOrgTree_UnitMoveVsPositionCreate(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	const iterations = 20
	for iter := 0; iter < iterations; iter++ {
		t.Run(fmt.Sprintf("iter%02d", iter), func(t *testing.T) {
			companyA := mustCreateCompany(t, store, fmt.Sprintf("CONCMVA%02d", iter))
			companyB := mustCreateCompany(t, store, fmt.Sprintf("CONCMVB%02d", iter))
			territory := mustCreateUnit(t, store, "territory", companyA.ID, fmt.Sprintf("CONCMVT%02d", iter))
			// Deliberately no position under territory yet — an empty subtree is what lets the
			// pre-fix move check pass on its own stale-but-consistent snapshot (see doc comment).

			var moveErr, createErr error
			// CreatePosition does one snapshot-dependent read before its insert; UpdateOrgUnit
			// does several (GetOrgUnit, two resolveRootCompany walks, then subtreeHasPositions)
			// before its own write. Started at the exact same instant, CreatePosition's shorter
			// path reliably finishes and commits before UpdateOrgUnit ever reaches its critical
			// read, so the race window is missed almost every time. A small calibrated delay on
			// the create side (empirically: ~450-900us on this stack) lands its check inside that
			// window instead, making the race reliably observable rather
			// than left to chance. It has no bearing on post-fix
			// correctness: the advisory lock serializes both paths regardless of timing.
			delay := 600 * time.Microsecond
			errs := startBarrier(2, func(i int) error {
				switch i {
				case 0:
					_, err := store.UpdateOrgUnit(ctx, "test-actor", territory.ID, &companyB.ID, territory.Code, territory.Name, true)
					return err
				default:
					time.Sleep(delay)
					_, err := store.CreatePosition(ctx, "test-actor", companyA.ID, fmt.Sprintf("CONCMVP%02d", iter), "Racing Position", territory.ID)
					return err
				}
			})
			moveErr, createErr = errs[0], errs[1]

			failures := 0
			if moveErr != nil {
				failures++
			}
			if createErr != nil {
				failures++
			}
			if failures != 1 {
				t.Fatalf("REGRESSION iter %d: expected exactly one of {move, create-position} to fail, got moveErr=%v createErr=%v (both nil = the concurrent bypass committed; both non-nil = an unrelated double failure)", iter, moveErr, createErr)
			}

			// Invariant check regardless of which side failed: every position under territory's
			// CURRENT org_unit tree location must have company_id equal to territory's actual
			// resolved root company. Walk territory's own chain to find that root.
			chain := walkParentChain(t, store, territory.ID, 32)
			actualRoot := chain[len(chain)-1]

			rows, err := store.Subtree(ctx, actualRoot)
			if err != nil {
				t.Fatalf("iter %d: subtree of resolved root: %v", iter, err)
			}
			subtreeIDs := map[uuid.UUID]bool{}
			for _, u := range rows {
				subtreeIDs[u.ID] = true
			}
			if !subtreeIDs[territory.ID] {
				// territory's resolved root must contain territory itself; if not, something
				// else is broken (not this invariant), fail loudly with detail.
				t.Fatalf("iter %d: territory %s not found in its own resolved root %s's subtree", iter, territory.ID, actualRoot)
			}

			positions, _, err := store.ListPositions(ctx, companyA.ID, 1, 50)
			if err != nil {
				t.Fatalf("iter %d: list positions for company A: %v", iter, err)
			}
			for _, p := range positions {
				if p.OrgUnitID == territory.ID && p.CompanyID != actualRoot {
					t.Fatalf("REGRESSION iter %d: position %s declared=%s actual=%s (org_unit %s's resolved root) — the cross-company invariant violation", iter, p.ID, p.CompanyID, actualRoot, territory.ID)
				}
			}
			positionsB, _, err := store.ListPositions(ctx, companyB.ID, 1, 50)
			if err != nil {
				t.Fatalf("iter %d: list positions for company B: %v", iter, err)
			}
			for _, p := range positionsB {
				if p.OrgUnitID == territory.ID && p.CompanyID != actualRoot {
					t.Fatalf("REGRESSION iter %d: position %s declared=%s actual=%s (org_unit %s's resolved root) — the cross-company invariant violation", iter, p.ID, p.CompanyID, actualRoot, territory.ID)
				}
			}
		})
	}
}

// TestConcurrentOrgTree_SiblingSwapCycle races a parent swap: two sibling org
// units under the SAME company swap parents concurrently (A's new parent becomes B, B's new
// parent becomes A). Pre-fix: UpdateOrgUnit's app-level cycle check walks each unit's OWN subtree
// (a leaf has none) before either transaction commits — both pass, both commit, and the two
// units now point at each other: a 2-node parent cycle the store's own cycle check was supposed
// to prevent (the store's cycle check runs before its transaction). Post-fix: the advisory lock serializes the two UpdateOrgUnit calls; whichever commits
// first makes its new parent chain visible to the second, and the second's lock-protected
// re-check (store-level AND migration 0006's trigger backstop) detects the would-be cycle and
// RAISEs — exactly one of the two moves must fail, and the surviving parent chain must never
// contain a cycle, every iteration.
func TestConcurrentOrgTree_SiblingSwapCycle(t *testing.T) {
	admin := adminPool(t)
	resetOrgFixtures(t, admin)
	store := newTestStore(t)
	ctx := context.Background()

	const iterations = 20
	for iter := 0; iter < iterations; iter++ {
		t.Run(fmt.Sprintf("iter%02d", iter), func(t *testing.T) {
			company := mustCreateCompany(t, store, fmt.Sprintf("CONCSWC%02d", iter))
			unitA := mustCreateUnit(t, store, "territory", company.ID, fmt.Sprintf("CONCSWA%02d", iter))
			unitB := mustCreateUnit(t, store, "territory", company.ID, fmt.Sprintf("CONCSWB%02d", iter))

			errs := startBarrier(2, func(i int) error {
				switch i {
				case 0:
					_, err := store.UpdateOrgUnit(ctx, "test-actor", unitA.ID, &unitB.ID, unitA.Code, unitA.Name, true)
					return err
				default:
					_, err := store.UpdateOrgUnit(ctx, "test-actor", unitB.ID, &unitA.ID, unitB.Code, unitB.Name, true)
					return err
				}
			})
			aErr, bErr := errs[0], errs[1]

			failures := 0
			if aErr != nil {
				failures++
			}
			if bErr != nil {
				failures++
			}
			if failures != 1 {
				t.Fatalf("REGRESSION iter %d: expected exactly one of {A→B, B→A} to fail, got aErr=%v bErr=%v (both nil = the sibling-swap cycle committed; both non-nil = an unrelated double failure)", iter, aErr, bErr)
			}

			assertNoCycle(t, store, unitA.ID)
			assertNoCycle(t, store, unitB.ID)
		})
	}
}
