// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
)

// TestIntersection_AllChildrenMustHold: `viewer = this AND on_deal` grants only to a subject that
// holds both; a union containing the intersection still short-circuits on its other child.
func TestIntersection_AllChildrenMustHold(t *testing.T) {
	ctx := context.Background()
	model, err := LoadModel([]byte(`{
	  "ix_line": {
	    "company_module": {"this": true},
	    "on_deal": {"this": true},
	    "side": {"this": true},
	    "viewer": {"intersection": [{"computedUserset": "side"}, {"computedUserset": "on_deal"}]},
	    "reader": {"union": [{"this": true}, {"computedUserset": "viewer"}]},
	    "ref": {"this": true},
	    "broken": {"intersection": [{"computedUserset": "side"}, {"tupleToUserset": {"tupleset": "ref", "computedUserset": "viewer"}}]}
	  }}`))
	if err != nil {
		t.Fatal(err)
	}
	pool := authzPool(t)
	eng := &Engine{Pool: pool, Model: model}
	clear := func() { _, _ = pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'ix-%'`) }
	clear()
	t.Cleanup(clear)
	insert := func(oid, rel, sid string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('ix_line',$1,$2,'user',$3,'') ON CONFLICT DO NOTHING`, oid, rel, sid); err != nil {
			t.Fatal(err)
		}
	}
	insert("ix-1", "side", "both")
	insert("ix-1", "on_deal", "both")
	insert("ix-1", "side", "side-only")
	insert("ix-1", "on_deal", "deal-only")
	insert("ix-1", "reader", "direct")

	want := map[string]map[string]bool{
		"viewer": {"both": true, "side-only": false, "deal-only": false, "direct": false, "nobody": false},
		"reader": {"both": true, "side-only": false, "deal-only": false, "direct": true, "nobody": false},
	}
	// A child that errors (a ref tuple to a type the model does not know) fails the whole check.
	if _, err := pool.Exec(ctx, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('ix_line','ix-1','ref','ghost_type','g-1','') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx, "ix_line", "ix-1", "broken", "user", "both"); err == nil {
		t.Fatal("an erroring child must fail the intersection, never decide it")
	}
	for rel, subjects := range want {
		for subj, allowed := range subjects {
			got, err := eng.Check(ctx, "ix_line", "ix-1", rel, "user", subj)
			if err != nil || got != allowed {
				t.Fatalf("%s for %s = %v, %v; want %v", rel, subj, got, err, allowed)
			}
		}
	}
}
