// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"os"
	"testing"
)

// TestCheckInCompany_SkipsForeignUsersets: a position, group or member userset from another
// company grants nothing when the check is bound to a company, while plain Check still resolves
// it. The tuple `doc#viewer @ position:B#holder` is exactly what a cross-company grant writes.
func TestCheckInCompany_SkipsForeignUsersets(t *testing.T) {
	ctx := context.Background()
	modelData, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatal(err)
	}
	model, err := LoadModel(modelData)
	if err != nil {
		t.Fatal(err)
	}
	// A module-shaped object type the base model does not define: add a minimal "cf_doc".
	model["cf_doc"] = map[string]Expr{"viewer": model["position"]["holder"]}
	pool := authzPool(t)
	eng := &Engine{Pool: pool, Model: model}

	clear := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'cf-%' OR subject_id LIKE 'cf-%'`)
	}
	clear()
	t.Cleanup(clear)
	insert := func(ot, oid, r, st, sid, sr string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, ot, oid, r, st, sid, sr); err != nil {
			t.Fatal(err)
		}
	}
	const companyA, companyB, user = "cf-A", "cf-B", "cf-user"
	// position cf-pos in B, group cf-grp in B, member cf-mem in B; all held by / containing user.
	insert("position", "cf-pos", "company", "company", companyB, "")
	insert("position", "cf-pos", "holder", "user", user, "")
	insert("group", "cf-grp", "company", "company", companyB, "")
	insert("group", "cf-grp", "member", "user", user, "")
	insert("company", companyB, "member", "member", "cf-mem", "mapped_user")
	insert("member", "cf-mem", "mapped_user", "user", user, "")
	// Three objects in A, each shared to one of those subjects.
	insert("cf_doc", "cf-doc-pos", "viewer", "position", "cf-pos", "holder")
	insert("cf_doc", "cf-doc-grp", "viewer", "group", "cf-grp", "member")
	insert("cf_doc", "cf-doc-mem", "viewer", "member", "cf-mem", "mapped_user")

	for _, obj := range []string{"cf-doc-pos", "cf-doc-grp", "cf-doc-mem"} {
		if ok, err := eng.Check(ctx, "cf_doc", obj, "viewer", "user", user); err != nil || !ok {
			t.Fatalf("%s: unbound Check = %v, %v; want allowed", obj, ok, err)
		}
		if ok, err := eng.CheckInCompany(ctx, "cf_doc", obj, "viewer", "user", user, companyA); err != nil || ok {
			t.Fatalf("%s: CheckInCompany(A) = %v, %v; want denied, the subject belongs to B", obj, ok, err)
		}
		if ok, err := eng.CheckInCompany(ctx, "cf_doc", obj, "viewer", "user", user, companyB); err != nil || !ok {
			t.Fatalf("%s: CheckInCompany(B) = %v, %v; want allowed", obj, ok, err)
		}
	}
	// A direct user subject is never company-scoped.
	insert("cf_doc", "cf-doc-direct", "viewer", "user", user, "")
	if ok, err := eng.CheckInCompany(ctx, "cf_doc", "cf-doc-direct", "viewer", "user", user, companyA); err != nil || !ok {
		t.Fatalf("direct user: CheckInCompany(A) = %v, %v; want allowed", ok, err)
	}
}
