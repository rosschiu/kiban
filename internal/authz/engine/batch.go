// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"sync"
)

// batchCan is single-subject: one actor checked against many (objectType, objectId, relation)
// pairs — never many actors in one call. That invariant is what makes sharing
// one memo across an entire batch sound — every item's recursion tree resolves the SAME final
// subject, so (objType,objID,rel) alone is a safe memo key with no subject component.
//
// batchCan is CONCURRENT. A worker pool of 8
// goroutines pulls items off one channel and evaluates them against a single *pgxpool.Pool
// (max conns >= 10, so up to 8 concurrent in-flight queries never starve waiting for a
// connection). The memo is a syncMapMemo (sync.Map) shared by every worker — still sound under
// concurrency because Postgres tuple rows are immutable for the duration of one batch (no
// writer runs concurrently with a batchCan call in this design) and the memoized value for a
// given (objType,objID,rel) key is the same regardless of which goroutine computes it first;
// a duplicate concurrent computation of the same key is wasted work, never a correctness bug.

// syncMapMemo is the concurrency-safe memo used by BatchCan; mapMemo (eval.go) remains the
// private, non-thread-safe memo for a single top-level Check.
type syncMapMemo struct {
	m sync.Map
}

func (s *syncMapMemo) load(key string) (bool, bool) {
	v, ok := s.m.Load(key)
	if !ok {
		return false, false
	}
	return v.(bool), true
}

func (s *syncMapMemo) store(key string, v bool) {
	// LoadOrStore keeps the first-computed value stable if two workers race on the same key —
	// both computed the same result (memo values are deterministic given fixed tuple data), so
	// either winning is fine; LoadOrStore just avoids a redundant overwrite.
	s.m.LoadOrStore(key, v)
}

// batchWorkers is the fixed worker-pool size (the benchmark in internal/authz/bench measures it).
const batchWorkers = 8

// BatchItem is one (object,relation) pair evaluated for the batch's fixed subject.
type BatchItem struct {
	ObjType, ObjID, Rel string
}

// BatchResult is the outcome for one BatchItem, in request order (order is preserved even
// though evaluation is concurrent — each item's result is written to its own index).
type BatchResult struct {
	Item    BatchItem
	Allowed bool
	Err     error
}

// BatchCan evaluates every item against the SAME subject, concurrently across batchWorkers
// goroutines, sharing one syncMapMemo across the whole batch. Results are returned in the same
// order as items.
func (en *Engine) BatchCan(ctx context.Context, subjType, subjID string, items []BatchItem) []BatchResult {
	results := make([]BatchResult, len(items))
	if len(items) == 0 {
		return results
	}

	shared := &syncMapMemo{}

	type job struct {
		idx  int
		item BatchItem
	}
	jobs := make(chan job)

	workers := batchWorkers
	if len(items) < workers {
		workers = len(items)
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			ec := en.newEvalCtx(subjType, subjID, shared) // own in-progress set, shared memo
			for j := range jobs {
				allowed, err := ec.check(ctx, j.item.ObjType, j.item.ObjID, j.item.Rel, 0)
				results[j.idx] = BatchResult{Item: j.item, Allowed: allowed, Err: err}
			}
		}()
	}

	for i, it := range items {
		jobs <- job{idx: i, item: it}
	}
	close(jobs)
	wg.Wait()

	return results
}
