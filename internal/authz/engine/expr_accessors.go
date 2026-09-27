// SPDX-License-Identifier: Apache-2.0

package engine

// Exported read-only accessors for Expr's otherwise-unexported fields — needed by
// internal/authz/harness (a different package) to translate a Model into an
// OpenFGA authorization model without exposing Expr's internals for general use (no setters,
// no way to construct an Expr except via UnmarshalJSON's subset wall).

// IsThis reports whether e is a `this` leaf.
func (e Expr) IsThis() bool { return e.kind == kindThis }

// ComputedUsersetRel returns the target relation name for a `computedUserset` leaf, or "" if
// e is not one.
func (e Expr) ComputedUsersetRel() string {
	if e.kind != kindComputedUserset {
		return ""
	}
	return e.computedUserset
}

// TupleToUsersetExpr returns the `tupleToUserset` payload, or nil if e is not one.
func (e Expr) TupleToUsersetExpr() *TupleToUserset {
	if e.kind != kindTupleToUserset {
		return nil
	}
	return e.tupleToUserset
}

// UnionChildren returns the `union` children, or nil if e is not one.
func (e Expr) UnionChildren() []Expr {
	if e.kind != kindUnion {
		return nil
	}
	return e.union
}
