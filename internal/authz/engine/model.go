// SPDX-License-Identifier: Apache-2.0

// Package engine is the evaluator for the supported Zanzibar subset (this, computedUserset,
// tupleToUserset, union). vectors.json is the regression floor and model.json is the
// relations-JSON translation of internal/authz/harness/model.fga.
package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// exprKind identifies which of the four subset constructs a relation-definition
// expression uses.
type exprKind int

const (
	kindThis exprKind = iota
	kindComputedUserset
	kindTupleToUserset
	kindUnion
)

// TupleToUserset is the `X from tupleset` construct: for every tuple (obj, Tupleset, X),
// resolve check(X, ComputedUserset, subject).
type TupleToUserset struct {
	Tupleset        string `json:"tupleset"`
	ComputedUserset string `json:"computedUserset"`
}

// Expr is a relation-definition expression restricted to the supported subset. Any other
// OpenFGA construct (intersection, exclusion, wildcard, condition, ...) is rejected at
// json.Unmarshal time — the subset wall.
type Expr struct {
	kind            exprKind
	this            bool
	computedUserset string
	tupleToUserset  *TupleToUserset
	union           []Expr
}

// UnmarshalJSON enforces the subset wall: a relation expression object must carry exactly
// one recognized key. Any other key (including known-outside-subset names like
// "intersection", "exclusion", "wildcard", "condition") is rejected with the offending key
// named in the error, fail-closed.
func (e *Expr) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("relation expr: not a JSON object: %w", err)
	}
	if len(raw) != 1 {
		return fmt.Errorf("relation expr: expected exactly 1 key, got %d (%v)", len(raw), slices.Sorted(maps.Keys(raw)))
	}
	for k, v := range raw {
		switch k {
		case "this":
			var b bool
			if err := json.Unmarshal(v, &b); err != nil {
				return fmt.Errorf(`relation expr: "this" must be a JSON bool: %w`, err)
			}
			if !b {
				return fmt.Errorf(`relation expr: "this": false has no meaning in the subset`)
			}
			e.kind, e.this = kindThis, true
		case "computedUserset":
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return fmt.Errorf(`relation expr: "computedUserset" must be a string: %w`, err)
			}
			if s == "" {
				return fmt.Errorf(`relation expr: "computedUserset" must name a relation`)
			}
			e.kind, e.computedUserset = kindComputedUserset, s
		case "tupleToUserset":
			var t TupleToUserset
			if err := json.Unmarshal(v, &t); err != nil {
				return fmt.Errorf(`relation expr: "tupleToUserset": %w`, err)
			}
			if t.Tupleset == "" || t.ComputedUserset == "" {
				return fmt.Errorf(`relation expr: "tupleToUserset" requires non-empty tupleset and computedUserset`)
			}
			e.kind, e.tupleToUserset = kindTupleToUserset, &t
		case "union":
			var children []Expr
			if err := json.Unmarshal(v, &children); err != nil {
				return fmt.Errorf(`relation expr: "union": %w`, err)
			}
			if len(children) == 0 {
				return fmt.Errorf(`relation expr: "union" must have at least one child`)
			}
			e.kind, e.union = kindUnion, children
		default:
			return fmt.Errorf(
				"relation expr: construct %q is outside the supported subset (allowed: this, computedUserset, tupleToUserset, union)",
				k,
			)
		}
	}
	return nil
}

// Model is object type -> relation name -> definition expression. Hand-translated from
// internal/authz/harness/model.fga into the module fragment "relations" JSON shape.
type Model map[string]map[string]Expr

// LoadModel parses and validates a model.json document. Validation beyond the per-expression
// subset wall (enforced during Unmarshal): every computedUserset target and every
// tupleToUserset.tupleset target must name a relation that exists on the SAME object type
// (both are same-object references — computedUserset always re-evaluates the current object;
// a tupleset is a relation on the current object holding parent/child refs). tupleToUserset's
// computedUserset half names a relation on whatever type the tupleset tuples happen to point
// at, which is only known at eval time from the tuple rows themselves — checked there,
// fail-closed on lookup miss (unknown type/relation).
func LoadModel(data []byte) (Model, error) {
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("model: empty")
	}
	for typ, rels := range m {
		for rel, expr := range rels {
			if err := validateSelfRefs(m, typ, rel, expr); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// Merge returns a new Model containing the receiver's types plus every type from other. A
// type declared on both sides is an error: two module fragments
// declaring one object type would otherwise resolve last-wins by row order, so the effective
// model could flip between loads. Callers name the offending modules.
func (m Model) Merge(other Model) (Model, error) {
	out := make(Model, len(m)+len(other))
	for k, v := range m {
		out[k] = v
	}
	for k, v := range other {
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("model: object type %q is declared by more than one model", k)
		}
		out[k] = v
	}
	return out, nil
}

// ValidateTupleToUsersetTargets is the cross-type half LoadModel cannot do on a fragment alone:
// every tupleToUserset.computedUserset in m must name a relation defined on at least one type of
// m (the tupleset's tuples can only ever point at types in the effective model). Callers run it
// on the EFFECTIVE model (base + fragment) — internal/modvalidate at install time and
// internal/authz/fragment.Load after merge — so a fragment referencing e.g. `company_module#member`
// fails loudly there instead of as UNKNOWN_RELATION at eval time.
func (m Model) ValidateTupleToUsersetTargets() error {
	defined := map[string]bool{}
	for _, rels := range m {
		for rel := range rels {
			defined[rel] = true
		}
	}
	var walk func(typ, rel string, e Expr) error
	walk = func(typ, rel string, e Expr) error {
		if ttu := e.tupleToUserset; ttu != nil && !defined[ttu.ComputedUserset] {
			return fmt.Errorf("model: %s#%s: tupleToUserset computedUserset %q is not defined on any type of the effective model", typ, rel, ttu.ComputedUserset)
		}
		for _, child := range e.union {
			if err := walk(typ, rel, child); err != nil {
				return err
			}
		}
		return nil
	}
	for typ, rels := range m {
		for rel, expr := range rels {
			if err := walk(typ, rel, expr); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateCompanyModuleAnchor enforces the module-contract rule every FRAGMENT model must meet
// (run on the fragment alone, never on the merged model — base types carry no anchor): each
// declared object type defines `company_module` as a direct (`{"this": true}`) relation. The
// decision layer binds every company-scope object check to the request's company through that
// relation, so a type without it could never be checked at all.
func (m Model) ValidateCompanyModuleAnchor() error {
	for typ, rels := range m {
		anchor, ok := rels["company_module"]
		if !ok || !anchor.IsThis() {
			return fmt.Errorf("model: object type %q must define relation \"company_module\" as {\"this\": true} (the company anchor every module object carries)", typ)
		}
	}
	return nil
}

func validateSelfRefs(m Model, typ, rel string, e Expr) error {
	switch e.kind {
	case kindThis:
		return nil
	case kindComputedUserset:
		if _, ok := m[typ][e.computedUserset]; !ok {
			return fmt.Errorf("model: %s#%s: computedUserset %q not defined on type %q", typ, rel, e.computedUserset, typ)
		}
		return nil
	case kindTupleToUserset:
		if _, ok := m[typ][e.tupleToUserset.Tupleset]; !ok {
			return fmt.Errorf("model: %s#%s: tupleToUserset tupleset %q not defined on type %q", typ, rel, e.tupleToUserset.Tupleset, typ)
		}
		return nil
	case kindUnion:
		for _, child := range e.union {
			if err := validateSelfRefs(m, typ, rel, child); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("model: %s#%s: unrecognized expression kind", typ, rel)
	}
}
