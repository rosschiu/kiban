// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxDepth is the fail-closed recursion fence.
const MaxDepth = 32

// CheckError is a fail-closed evaluation error: unknown type, unknown relation, or
// recursion past MaxDepth. Never treated as allow by any caller.
type CheckError struct {
	Code string // UNKNOWN_TYPE | UNKNOWN_RELATION | DEPTH_EXCEEDED
	Msg  string
}

func (e *CheckError) Error() string { return e.Code + ": " + e.Msg }

// Engine evaluates checks against a Model over authz.tuple, via a shared *pgxpool.Pool (the
// concurrent batchCan needs a pool with max conns >= 10, one pool shared by the worker
// goroutines).
type Engine struct {
	Pool  *pgxpool.Pool
	Model Model
}

const sqlTupleRows = `SELECT subject_type, subject_id, subject_relation
FROM authz.tuple WHERE object_type = $1 AND object_id = $2 AND relation = $3`

type tupleRow struct {
	subjectType, subjectID, subjectRelation string
}

func (en *Engine) fetchRows(ctx context.Context, objType, objID, rel string) ([]tupleRow, error) {
	rows, err := en.Pool.Query(ctx, sqlTupleRows, objType, objID, rel)
	if err != nil {
		return nil, fmt.Errorf("query tuple rows: %w", err)
	}
	defer rows.Close()
	var out []tupleRow
	for rows.Next() {
		var r tupleRow
		if err := rows.Scan(&r.subjectType, &r.subjectID, &r.subjectRelation); err != nil {
			return nil, fmt.Errorf("scan tuple row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tuple rows: %w", err)
	}
	return out, nil
}

// memo abstracts the (objType,objID,rel) -> allowed cache an evalCtx uses. A single top-level
// Check uses a private, non-thread-safe mapMemo; the concurrent batchCan (batch.go) uses a
// syncMapMemo shared across its worker goroutines — sound only because a batch is one subject
// checked against many (object,relation) pairs, so the memo's key never needs a subject
// component. See batch.go's file comment for the full invariant note.
type memo interface {
	load(key string) (bool, bool)
	store(key string, v bool)
}

type mapMemo map[string]bool

func (m mapMemo) load(key string) (bool, bool) { v, ok := m[key]; return v, ok }
func (m mapMemo) store(key string, v bool)     { m[key] = v }

func memoKey(objType, objID, rel string) string {
	return objType + "\x00" + objID + "\x00" + rel
}

// evalCtx carries the state that must NOT survive a single top-level Check call: the memo
// (obj,rel) -> bool, fixed for the duration of one check because the subject never changes
// within a single check's recursion tree (computedUserset/tupleToUserset/union all resolve
// the SAME final subject).
type evalCtx struct {
	engine           *Engine
	subjType, subjID string
	memo             memo
	// visiting marks the nodes on the CURRENT recursion path (the memo's in-progress
	// marker): re-entering one is a tuple cycle, answered false for that path
	// (the node contributes nothing to itself — OpenFGA's answer too), never DEPTH_EXCEEDED.
	// Owned by one goroutine — a batch worker gets its own, sharing only the memo.
	visiting map[string]bool
	// cuts counts cycle cuts taken so far. A false computed while a cut happened beneath it is
	// path-dependent (the in-progress node might still resolve true), so it is not memoized;
	// a true is always definitive.
	cuts int
}

// newEvalCtx starts a fresh in-progress set over m — one per goroutine.
func (en *Engine) newEvalCtx(subjType, subjID string, m memo) *evalCtx {
	return &evalCtx{engine: en, subjType: subjType, subjID: subjID, memo: m, visiting: map[string]bool{}}
}

// Check answers whether (subjType,subjID) has relation `rel` to (objType,objID). Fresh memo
// per call — see evalCtx doc.
func (en *Engine) Check(ctx context.Context, objType, objID, rel, subjType, subjID string) (bool, error) {
	ec := en.newEvalCtx(subjType, subjID, make(mapMemo))
	return ec.check(ctx, objType, objID, rel, 0)
}

func (ec *evalCtx) check(ctx context.Context, objType, objID, rel string, depth int) (bool, error) {
	key := memoKey(objType, objID, rel)
	if v, ok := ec.memo.load(key); ok {
		return v, nil
	}
	if ec.visiting[key] {
		ec.cuts++
		return false, nil
	}
	if depth > MaxDepth {
		return false, &CheckError{Code: "DEPTH_EXCEEDED", Msg: fmt.Sprintf("check(%s:%s#%s) exceeded max depth %d", objType, objID, rel, MaxDepth)}
	}
	typeDef, ok := ec.engine.Model[objType]
	if !ok {
		return false, &CheckError{Code: "UNKNOWN_TYPE", Msg: fmt.Sprintf("object type %q not in model", objType)}
	}
	expr, ok := typeDef[rel]
	if !ok {
		return false, &CheckError{Code: "UNKNOWN_RELATION", Msg: fmt.Sprintf("relation %q not defined on type %q", rel, objType)}
	}
	ec.visiting[key] = true
	cutsBefore := ec.cuts
	result, err := ec.evalExpr(ctx, objType, objID, rel, expr, depth)
	delete(ec.visiting, key)
	if err != nil {
		return false, err
	}
	if result || ec.cuts == cutsBefore {
		ec.memo.store(key, result)
	}
	return result, nil
}

func (ec *evalCtx) evalExpr(ctx context.Context, objType, objID, rel string, e Expr, depth int) (bool, error) {
	switch e.kind {
	case kindThis:
		return ec.evalThis(ctx, objType, objID, rel, depth)
	case kindComputedUserset:
		return ec.check(ctx, objType, objID, e.computedUserset, depth+1)
	case kindTupleToUserset:
		return ec.evalTupleToUserset(ctx, objType, objID, rel, e.tupleToUserset, depth)
	case kindUnion:
		for _, child := range e.union {
			ok, err := ec.evalExpr(ctx, objType, objID, rel, child, depth)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, &CheckError{Code: "UNKNOWN_RELATION", Msg: "unrecognized expression kind"}
	}
}

// evalThis: direct tuple (obj,rel,subject) exists, OR a userset tuple (obj,rel,X#r) exists
// with check(X,r,subject) true. Both direct and userset rows come from one query on the SQL
// lookup shape (object_type,object_id,relation) — a single prepared statement per lookup
// shape; pgx caches the statement for this exact SQL text automatically.
func (ec *evalCtx) evalThis(ctx context.Context, objType, objID, rel string, depth int) (bool, error) {
	rows, err := ec.engine.fetchRows(ctx, objType, objID, rel)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.subjectRelation == "" {
			if r.subjectType == ec.subjType && r.subjectID == ec.subjID {
				return true, nil
			}
			continue
		}
		// Userset subject: X#r. Recurse with the SAME final subject.
		ok, err := ec.check(ctx, r.subjectType, r.subjectID, r.subjectRelation, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// evalTupleToUserset: for every tuple (obj, tupleset, X) [direct object refs only — tupleset
// relations are structural parent/child links, never userset-valued in this model], resolve
// check(X, computedUserset, subject); any true short-circuits.
func (ec *evalCtx) evalTupleToUserset(ctx context.Context, objType, objID, rel string, ttu *TupleToUserset, depth int) (bool, error) {
	rows, err := ec.engine.fetchRows(ctx, objType, objID, ttu.Tupleset)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.subjectRelation != "" {
			// A userset-valued tupleset row is outside the subset's tupleToUserset shape;
			// skip rather than misinterpret (fail-closed: never treated as a match).
			continue
		}
		ok, err := ec.check(ctx, r.subjectType, r.subjectID, ttu.ComputedUserset, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
