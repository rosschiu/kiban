// SPDX-License-Identifier: Apache-2.0

//go:build harness

package harness

import (
	"context"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// TestHarnessIntersection: `and` evaluates identically in the engine and in OpenFGA, for every
// combination of the two facts, alone and inside a union.
func TestHarnessIntersection(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping (see TestHarness's own skip message)")
	}
	ctx := context.Background()
	baseURL, stop, err := StartOpenFGA(ctx, 28084, 28085)
	if err != nil {
		t.Fatalf("start openfga container: %v", err)
	}
	t.Cleanup(stop)
	client := NewClient(baseURL)
	pool := authzPool(t)

	model, err := engine.LoadModel([]byte(`{
	  "user": {},
	  "company_module": {"member": {"this": true}},
	  "ix_line": {
	    "company_module": {"this": true},
	    "on_deal": {"this": true},
	    "side": {"this": true},
	    "viewer": {"intersection": [{"computedUserset": "side"}, {"computedUserset": "on_deal"}]},
	    "reader": {"union": [{"this": true}, {"computedUserset": "viewer"}]}
	  }}`))
	if err != nil {
		t.Fatal(err)
	}
	fgaModelDoc, err := BuildOpenFGAModel(model, "testdata_intersection.fga")
	if err != nil {
		t.Fatalf("BuildOpenFGAModel: %v", err)
	}
	storeID, err := client.CreateStore(ctx, "kiban-harness-intersection")
	if err != nil {
		t.Fatal(err)
	}
	modelID, err := client.WriteAuthorizationModel(ctx, storeID, fgaModelDoc)
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: model}

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-ix-%'`)
	t.Cleanup(func() { mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-ix-%'`) })
	write := func(rel, user string) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('ix_line','harn-ix-1',$1,'user',$2,'') ON CONFLICT DO NOTHING`, rel, user)
		if err := client.WriteTupleSingle(ctx, storeID, TupleKey{User: "user:" + user, Relation: rel, Object: "ix_line:harn-ix-1"}); err != nil {
			t.Fatalf("openfga write %s %s: %v", rel, user, err)
		}
	}
	write("side", "both")
	write("on_deal", "both")
	write("side", "side-only")
	write("on_deal", "deal-only")
	write("reader", "direct")

	for _, rel := range []string{"viewer", "reader"} {
		for _, user := range []string{"both", "side-only", "deal-only", "direct", "nobody"} {
			eng, err := en.Check(ctx, "ix_line", "harn-ix-1", rel, "user", user)
			if err != nil {
				t.Fatalf("engine %s %s: %v", rel, user, err)
			}
			fga, err := client.Check(ctx, storeID, modelID, TupleKey{User: "user:" + user, Relation: rel, Object: "ix_line:harn-ix-1"})
			if err != nil {
				t.Fatalf("openfga %s %s: %v", rel, user, err)
			}
			if eng != fga {
				t.Fatalf("DIVERGENCE %s for %s: engine=%v openfga=%v", rel, user, eng, fga)
			}
		}
	}
}
