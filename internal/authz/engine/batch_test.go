// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestBatchCan is the behavioral suite for the concurrent worker-pool BatchCan:
// worker-pool sizing (fewer items than workers, more items than workers), the shared
// syncMapMemo under real concurrency, per-item error paths (UNKNOWN_TYPE, UNKNOWN_RELATION,
// DEPTH_EXCEEDED via a 34-link userset chain; a plain cycle answers false), partial failure
// (some items error, others still resolve correctly in the same batch), order preservation, and
// the len(items)==0 fast path. All fixture data lives under the 'batch-' namespace so it never
// collides with TestVectors' 'vec-' namespace sharing the same table.
func TestBatchCan(t *testing.T) {
	ctx := context.Background()

	modelData, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	pool := authzPool(t)

	if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'batch-%' OR subject_id LIKE 'batch-%'`); err != nil {
		t.Fatalf("clear batch- fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'batch-%' OR subject_id LIKE 'batch-%'`)
	})

	tuples := []struct {
		objType, objID, rel, subjType, subjID, subjRel string
	}{
		{"company", "batch-c1", "admin", "user", "batch-admin", ""},
		{"module", "batch-mod1", "editor", "user", "batch-editor-only", ""},
		// mutually recursive userset-subject loop, ported from vectors.json's cycle fixture
		{"member_directory", "batch-loop-a", "editor", "member_directory", "batch-loop-b", "editor"},
		{"member_directory", "batch-loop-b", "editor", "member_directory", "batch-loop-a", "editor"},
	}
	// A genuinely deep (acyclic) userset chain, MaxDepth+2 links, so the depth fence still
	// fires where no cycle cut applies.
	for i := 0; i < MaxDepth+2; i++ {
		tuples = append(tuples, struct{ objType, objID, rel, subjType, subjID, subjRel string }{
			"member_directory", fmt.Sprintf("batch-chain-%d", i), "editor", "member_directory", fmt.Sprintf("batch-chain-%d", i+1), "editor"})
	}
	batch := &pgx.Batch{}
	for _, tp := range tuples {
		batch.Queue(
			`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			tp.objType, tp.objID, tp.rel, tp.subjType, tp.subjID, tp.subjRel,
		)
	}
	br := pool.SendBatch(ctx, batch)
	for range tuples {
		if _, err := br.Exec(); err != nil {
			br.Close()
			t.Fatalf("insert fixture tuple: %v", err)
		}
	}
	if err := br.Close(); err != nil {
		t.Fatalf("close fixture batch: %v", err)
	}

	eng := &Engine{Pool: pool, Model: model}

	t.Run("empty batch returns empty results, no panic", func(t *testing.T) {
		results := eng.BatchCan(ctx, "user", "batch-admin", nil)
		if len(results) != 0 {
			t.Fatalf("want 0 results for nil items, got %d", len(results))
		}
		results = eng.BatchCan(ctx, "user", "batch-admin", []BatchItem{})
		if len(results) != 0 {
			t.Fatalf("want 0 results for empty items, got %d", len(results))
		}
	})

	t.Run("fewer items than the worker pool (workers clamps to len(items))", func(t *testing.T) {
		items := []BatchItem{
			{ObjType: "company", ObjID: "batch-c1", Rel: "admin"},
			{ObjType: "company", ObjID: "batch-c1", Rel: "viewer"},
		}
		results := eng.BatchCan(ctx, "user", "batch-admin", items)
		if len(results) != 2 {
			t.Fatalf("want 2 results, got %d", len(results))
		}
		if !results[0].Allowed || results[0].Err != nil {
			t.Fatalf("item 0 (direct admin grant): want allow/no-err, got allowed=%v err=%v", results[0].Allowed, results[0].Err)
		}
		if !results[1].Allowed || results[1].Err != nil {
			t.Fatalf("item 1 (viewer via union->computedUserset(admin)): want allow/no-err, got allowed=%v err=%v", results[1].Allowed, results[1].Err)
		}
	})

	t.Run("more items than the worker pool exercises the full 8-worker pool, preserves order", func(t *testing.T) {
		// 25 items > batchWorkers(8), all against the SAME subject/object/relation so the
		// shared syncMapMemo is hit concurrently by every worker for the identical key —
		// this is exactly the concurrency scenario the memo's LoadOrStore race-safety note
		// (batch.go) exists for.
		const n = 25
		items := make([]BatchItem, n)
		for i := 0; i < n; i++ {
			items[i] = BatchItem{ObjType: "company", ObjID: "batch-c1", Rel: "admin"}
		}
		results := eng.BatchCan(ctx, "user", "batch-admin", items)
		if len(results) != n {
			t.Fatalf("want %d results, got %d", n, len(results))
		}
		for i, r := range results {
			if r.Item != items[i] {
				t.Fatalf("result[%d].Item = %+v, want %+v (order must be preserved despite concurrent evaluation)", i, r.Item, items[i])
			}
			if r.Err != nil || !r.Allowed {
				t.Fatalf("result[%d]: want allow/no-err, got allowed=%v err=%v", i, r.Allowed, r.Err)
			}
		}
	})

	t.Run("mixed items: allow, deny, and each error kind in one batch (partial failure)", func(t *testing.T) {
		items := []BatchItem{
			{ObjType: "company", ObjID: "batch-c1", Rel: "admin"},                // allow (direct)
			{ObjType: "module", ObjID: "batch-mod1", Rel: "editor"},              // deny (different subject holds it)
			{ObjType: "nonexistent_type", ObjID: "x", Rel: "y"},                  // UNKNOWN_TYPE
			{ObjType: "company", ObjID: "batch-c1", Rel: "nonexistent_rel"},      // UNKNOWN_RELATION
			{ObjType: "member_directory", ObjID: "batch-chain-0", Rel: "editor"}, // DEPTH_EXCEEDED (34-link chain)
			{ObjType: "company", ObjID: "batch-c1", Rel: "viewer"},               // allow again — proves later items still resolve after earlier items error
			{ObjType: "member_directory", ObjID: "batch-loop-a", Rel: "editor"},  // deny, no error: a plain cycle is cut
		}
		results := eng.BatchCan(ctx, "user", "batch-admin", items)
		if len(results) != len(items) {
			t.Fatalf("want %d results, got %d", len(items), len(results))
		}

		if !results[0].Allowed || results[0].Err != nil {
			t.Fatalf("item 0: want allow/no-err, got allowed=%v err=%v", results[0].Allowed, results[0].Err)
		}
		if results[1].Allowed || results[1].Err != nil {
			t.Fatalf("item 1: want deny/no-err, got allowed=%v err=%v", results[1].Allowed, results[1].Err)
		}
		wantCode := func(i int, code string) {
			t.Helper()
			ce, ok := results[i].Err.(*CheckError)
			if !ok {
				t.Fatalf("item %d: want *CheckError, got %T: %v", i, results[i].Err, results[i].Err)
			}
			if ce.Code != code {
				t.Fatalf("item %d: want error code %s, got %s (%v)", i, code, ce.Code, ce)
			}
			if results[i].Allowed {
				t.Fatalf("item %d: an errored item must never report Allowed=true (fail-closed)", i)
			}
		}
		wantCode(2, "UNKNOWN_TYPE")
		wantCode(3, "UNKNOWN_RELATION")
		wantCode(4, "DEPTH_EXCEEDED")
		if !results[5].Allowed || results[5].Err != nil {
			t.Fatalf("item 5 (after 3 errored items): want allow/no-err, got allowed=%v err=%v — a batch error must not corrupt sibling items", results[5].Allowed, results[5].Err)
		}
		if results[6].Allowed || results[6].Err != nil {
			t.Fatalf("item 6 (userset cycle): want deny/no-err, got allowed=%v err=%v", results[6].Allowed, results[6].Err)
		}
		// Every result's Item echoes the input at that index.
		for i, r := range results {
			if r.Item != items[i] {
				t.Fatalf("result[%d].Item = %+v, want %+v", i, r.Item, items[i])
			}
		}
	})

	t.Run("concurrent calls to BatchCan on the same Engine do not race (fresh memo per call)", func(t *testing.T) {
		// Each call to BatchCan constructs its own evalCtx/syncMapMemo, so two goroutines
		// calling BatchCan concurrently on the same *Engine must not interfere. Run under
		// `go test -race` (Makefile's `make test`) to catch any shared-state bug.
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				items := []BatchItem{
					{ObjType: "company", ObjID: "batch-c1", Rel: "admin"},
					{ObjType: "company", ObjID: "batch-c1", Rel: "viewer"},
				}
				results := eng.BatchCan(ctx, "user", "batch-admin", items)
				for _, r := range results {
					if r.Err != nil || !r.Allowed {
						errs <- errAllowExpected(r)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})
}

func errAllowExpected(r BatchResult) error {
	return &CheckError{Code: "TEST_UNEXPECTED", Msg: "want allow/no-err for " + r.Item.ObjType + ":" + r.Item.ObjID + "#" + r.Item.Rel}
}
