// SPDX-License-Identifier: Apache-2.0

package engine

import "testing"

// TestExprAccessors covers the exported read-only accessors expr_accessors.go adds for
// internal/authz/harness's Model->OpenFGA translation. Each accessor must report true/non-nil
// only for its own Expr kind and the zero value/false for every other kind — the harness relies
// on this to distinguish leaf shapes without access to Expr's unexported fields.
func TestExprAccessors(t *testing.T) {
	model, err := LoadModel([]byte(`{
		"thing": {
			"this_leaf": {"this": true},
			"computed_leaf": {"computedUserset": "this_leaf"},
			"ttu_leaf": {"tupleToUserset": {"tupleset": "this_leaf", "computedUserset": "this_leaf"}},
			"union_leaf": {"union": [{"this": true}, {"computedUserset": "this_leaf"}]}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	thisExpr := model["thing"]["this_leaf"]
	computedExpr := model["thing"]["computed_leaf"]
	ttuExpr := model["thing"]["ttu_leaf"]
	unionExpr := model["thing"]["union_leaf"]

	t.Run("IsThis", func(t *testing.T) {
		if !thisExpr.IsThis() {
			t.Error("this leaf: IsThis() = false, want true")
		}
		for name, e := range map[string]Expr{"computed": computedExpr, "ttu": ttuExpr, "union": unionExpr} {
			if e.IsThis() {
				t.Errorf("%s leaf: IsThis() = true, want false", name)
			}
		}
	})

	t.Run("ComputedUsersetRel", func(t *testing.T) {
		if got := computedExpr.ComputedUsersetRel(); got != "this_leaf" {
			t.Errorf("computed leaf: ComputedUsersetRel() = %q, want %q", got, "this_leaf")
		}
		for name, e := range map[string]Expr{"this": thisExpr, "ttu": ttuExpr, "union": unionExpr} {
			if got := e.ComputedUsersetRel(); got != "" {
				t.Errorf("%s leaf: ComputedUsersetRel() = %q, want \"\"", name, got)
			}
		}
	})

	t.Run("TupleToUsersetExpr", func(t *testing.T) {
		got := ttuExpr.TupleToUsersetExpr()
		if got == nil {
			t.Fatal("ttu leaf: TupleToUsersetExpr() = nil, want non-nil")
		}
		if got.Tupleset != "this_leaf" || got.ComputedUserset != "this_leaf" {
			t.Errorf("ttu leaf: TupleToUsersetExpr() = %+v, want {this_leaf this_leaf}", got)
		}
		for name, e := range map[string]Expr{"this": thisExpr, "computed": computedExpr, "union": unionExpr} {
			if got := e.TupleToUsersetExpr(); got != nil {
				t.Errorf("%s leaf: TupleToUsersetExpr() = %+v, want nil", name, got)
			}
		}
	})

	t.Run("UnionChildren", func(t *testing.T) {
		got := unionExpr.UnionChildren()
		if len(got) != 2 {
			t.Fatalf("union leaf: UnionChildren() len = %d, want 2", len(got))
		}
		if !got[0].IsThis() {
			t.Errorf("union leaf: child 0 = %+v, want a this leaf", got[0])
		}
		if got[1].ComputedUsersetRel() != "this_leaf" {
			t.Errorf("union leaf: child 1 ComputedUsersetRel() = %q, want %q", got[1].ComputedUsersetRel(), "this_leaf")
		}
		for name, e := range map[string]Expr{"this": thisExpr, "computed": computedExpr, "ttu": ttuExpr} {
			if got := e.UnionChildren(); got != nil {
				t.Errorf("%s leaf: UnionChildren() = %+v, want nil", name, got)
			}
		}
	})
}
