// SPDX-License-Identifier: Apache-2.0

//go:build harness

package harness

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// excludedVectors are vectors.json cases NOT replayed against OpenFGA — a clear, understood
// OpenFGA-side subset difference: OpenFGA validates a relation's directly-
// assignable subject TYPES at tuple-write time (the model's `[...]` bracket in
// internal/authz/harness/model.fga); engine.Check has no such restriction (any row matching
// object/relation is read, regardless of subject type). Two vectors intentionally write a
// userset-subject tuple to a relation whose DSL bracket is `[user]` only
// (company_module#viewer <- company#viewer, member_directory#editor <- member_directory#editor)
// to prove the engine's more general evaluation — OpenFGA rejects writing those tuples
// outright, so there is nothing to differentially check. The two "error"-expect vectors
// (unknown type/relation) test engine-internal fail-closed error codes that don't
// have an OpenFGA equivalent to differentially compare against. The three cycle vectors write
// self-referential usersets (member_directory#editor, group#member) no DSL bracket admits, so
// they are excluded here and proven against OpenFGA on a dedicated model in TestHarnessCycle.
var excludedVectors = map[string]bool{
	"company-module-viewer-userset-subject-expansion":           true,
	"company-module-viewer-userset-subject-expansion-via-admin": true,
	"unknown-object-type-fails-closed":                          true,
	"unknown-relation-fails-closed":                             true,
	"userset-cycle-answers-false":                               true,
	"group-cycle-outsider-deny":                                 true,
	"group-cycle-member-of-a-allowed-on-b":                      true,
}

type vecTuple struct {
	ObjectType      string `json:"object_type"`
	ObjectID        string `json:"object_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation"`
}

type vecCase struct {
	Name     string `json:"name"`
	ObjType  string `json:"objType"`
	ObjID    string `json:"objID"`
	Rel      string `json:"rel"`
	SubjType string `json:"subjType"`
	SubjID   string `json:"subjID"`
	Expect   string `json:"expect"`
}

type vectorsFile struct {
	Tuples  []vecTuple `json:"tuples"`
	Vectors []vecCase  `json:"vectors"`
}

func openfgaUser(subjType, subjID, subjRel string) string {
	if subjRel != "" {
		return subjType + ":" + subjID + "#" + subjRel
	}
	return subjType + ":" + subjID
}

// TestHarness is the differential conformance harness (`make test-harness`). It skips
// LOUDLY (not silently) if Docker isn't available in the environment running the test.
func TestHarness(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("\n" + "=========================================================================\n" +
			"  WARNING: Docker is not available — skipping the OpenFGA differential\n" +
			"  harness (engine vs real OpenFGA). This test does NOT count as passing;\n" +
			"  it is not being run at all. Install/start Docker to exercise it.\n" +
			"=========================================================================")
	}

	ctx := context.Background()
	baseURL, stop, err := StartOpenFGA(ctx, 28080, 28081)
	if err != nil {
		t.Fatalf("start openfga container: %v", err)
	}
	t.Cleanup(stop)
	client := NewClient(baseURL)

	pool := authzPool(t)

	modelData, err := os.ReadFile(filepath.Join("..", "engine", "model.json"))
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := engine.LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	dslPath := "model.fga"
	fgaModelDoc, err := BuildOpenFGAModel(model, dslPath)
	if err != nil {
		t.Fatalf("BuildOpenFGAModel: %v", err)
	}

	storeID, err := client.CreateStore(ctx, "kiban-harness")
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	modelID, err := client.WriteAuthorizationModel(ctx, storeID, fgaModelDoc)
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}
	t.Logf("openfga store=%s model=%s", storeID, modelID)

	en := &engine.Engine{Pool: pool, Model: model}

	// --- (a) replay vectors.json ---
	vecBytes, err := os.ReadFile(filepath.Join("..", "engine", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var vf vectorsFile
	if err := json.Unmarshal(vecBytes, &vf); err != nil {
		t.Fatalf("unmarshal vectors.json: %v", err)
	}

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'vec-%' OR subject_id LIKE 'vec-%'`)
	for _, tp := range vf.Tuples {
		mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation)

		key := TupleKey{User: openfgaUser(tp.SubjectType, tp.SubjectID, tp.SubjectRelation), Relation: tp.Relation, Object: tp.ObjectType + ":" + tp.ObjectID}
		if err := client.WriteTupleSingle(ctx, storeID, key); err != nil {
			t.Logf("openfga: skipping unwritable vector tuple (expected for the documented userset-bracket cases): %+v: %v", tp, err)
		}
	}

	replayed, divergences := 0, 0
	for _, vec := range vf.Vectors {
		if excludedVectors[vec.Name] {
			continue
		}
		if vec.Expect != "allow" && vec.Expect != "deny" {
			continue
		}
		wantAllow := vec.Expect == "allow"

		engAllowed, engErr := en.Check(ctx, vec.ObjType, vec.ObjID, vec.Rel, vec.SubjType, vec.SubjID)
		if engErr != nil {
			t.Fatalf("vector %s: engine.Check unexpected error: %v", vec.Name, engErr)
		}
		if engAllowed != wantAllow {
			t.Fatalf("vector %s: engine disagrees with its OWN vectors.json floor (allowed=%v want=%v) — investigate before touching the harness", vec.Name, engAllowed, wantAllow)
		}

		fgaAllowed, fgaErr := client.Check(ctx, storeID, modelID, TupleKey{
			User: openfgaUser(vec.SubjType, vec.SubjID, ""), Relation: vec.Rel, Object: vec.ObjType + ":" + vec.ObjID,
		})
		if fgaErr != nil {
			t.Fatalf("vector %s: openfga Check error: %v", vec.Name, fgaErr)
		}
		replayed++
		if fgaAllowed != engAllowed {
			divergences++
			t.Errorf("DIVERGENCE vector %s: engine=%v openfga=%v — object=%s:%s#%s subject=%s:%s",
				vec.Name, engAllowed, fgaAllowed, vec.ObjType, vec.ObjID, vec.Rel, vec.SubjType, vec.SubjID)
		}
	}
	t.Logf("vectors.json replay: %d checks, %d divergences (excluded: %d)", replayed, divergences, len(excludedVectors))

	// --- (b) 5,000 seeded random checks over loadgen-shaped data ---
	rows, ids := defaultSmallLoadgen.Generate()
	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'hc%' OR subject_id LIKE 'hc%'`)
	if err := loadPostgresRows(ctx, pool, rows); err != nil {
		t.Fatalf("load postgres rows: %v", err)
	}
	if err := loadOpenFGARows(ctx, client, storeID, rows); err != nil {
		t.Fatalf("load openfga rows: %v", err)
	}
	if ids.HotCompanyID == "" || len(ids.HotBizIDs) == 0 || len(ids.OtherCompanyBiz) == 0 {
		t.Fatalf("smallLoadgen sample IDs missing: %+v", ids)
	}

	rng := rand.New(rand.NewSource(99))
	randChecks := 5000
	randDivergences := 0
	for i := 0; i < randChecks; i++ {
		var objType, objID, rel, subjType, subjID string
		switch i % 3 {
		case 0: // deep-inheritance allow: hot company admin can view any hot biz object
			objType, objID, rel = "timesheet_entry", ids.HotBizIDs[i%len(ids.HotBizIDs)], "viewer"
			subjType, subjID = "user", ids.HotCompanyAdminID
		case 1: // direct allow
			idx := i % len(ids.HotBizIDs)
			objType, objID, rel = "timesheet_entry", ids.HotBizIDs[idx], "viewer"
			subjType, subjID = "user", ids.HotGrantees[idx]
		case 2: // deny: hot admin against an unrelated company's object
			objType, objID, rel = "timesheet_entry", ids.OtherCompanyBiz[i%len(ids.OtherCompanyBiz)], "viewer"
			subjType, subjID = "user", ids.HotCompanyAdminID
		}
		_ = rng // reserved for future shuffling; deterministic index-based mix is sufficient here

		engAllowed, engErr := en.Check(ctx, objType, objID, rel, subjType, subjID)
		if engErr != nil {
			t.Fatalf("random check %d: engine error: %v", i, engErr)
		}
		fgaAllowed, fgaErr := client.Check(ctx, storeID, modelID, TupleKey{User: openfgaUser(subjType, subjID, ""), Relation: rel, Object: objType + ":" + objID})
		if fgaErr != nil {
			t.Fatalf("random check %d: openfga error: %v", i, fgaErr)
		}
		if engAllowed != fgaAllowed {
			randDivergences++
			t.Errorf("DIVERGENCE random check %d: engine=%v openfga=%v — object=%s:%s#%s subject=%s:%s",
				i, engAllowed, fgaAllowed, objType, objID, rel, subjType, subjID)
		}
	}
	t.Logf("random loadgen replay: %d checks, %d divergences", randChecks, randDivergences)

	if divergences+randDivergences > 0 {
		t.Fatalf("HARNESS FAILED: %d total divergences between engine and OpenFGA — see logged cases above", divergences+randDivergences)
	}
}

// TestHarnessPositionMutation is the position-holder differential proof: a
// userset-typed direct assignment (position#holder as a company_module tier's directly-
// assignable subject shape) round-trips through OpenFGA at all (the translator fix under test),
// AND a REPLACEMENT — grant, check, revoke, re-grant the same position to a DIFFERENT member,
// check both subjects — behaves identically in engine and OpenFGA. Static vectors.json can't
// express replacement (it's one fixed tuple set); this test can.
func TestHarnessPositionMutation(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping (see TestHarness's own skip message)")
	}

	ctx := context.Background()
	baseURL, stop, err := StartOpenFGA(ctx, 28082, 28083)
	if err != nil {
		t.Fatalf("start openfga container: %v", err)
	}
	t.Cleanup(stop)
	client := NewClient(baseURL)

	pool := authzPool(t)

	modelData, err := os.ReadFile(filepath.Join("..", "engine", "model.json"))
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := engine.LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	dslPath := "model.fga"
	fgaModelDoc, err := BuildOpenFGAModel(model, dslPath)
	if err != nil {
		t.Fatalf("BuildOpenFGAModel: %v", err)
	}

	storeID, err := client.CreateStore(ctx, "kiban-harness-mutation")
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	modelID, err := client.WriteAuthorizationModel(ctx, storeID, fgaModelDoc)
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}

	en := &engine.Engine{Pool: pool, Model: model}

	const (
		objType = "company_module"
		objID   = "harn-mut-c1/helpdesk"
		rel     = "editor"
		posID   = "harn-mut-p1"
		memberA = "harn-mut-mA"
		memberB = "harn-mut-mB"
		userA   = "harn-mut-uA"
		userB   = "harn-mut-uB"
	)

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-mut-%' OR subject_id LIKE 'harn-mut-%'`)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-mut-%' OR subject_id LIKE 'harn-mut-%'`)
	})

	writeBoth := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, ot, oid, r, st, sid, sr)
		key := TupleKey{User: openfgaUser(st, sid, sr), Relation: r, Object: ot + ":" + oid}
		if err := client.WriteTupleSingle(ctx, storeID, key); err != nil {
			t.Fatalf("openfga write %s:%s#%s @ %s: %v", ot, oid, r, key.User, err)
		}
	}
	deleteBoth := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_type=$1 AND object_id=$2 AND relation=$3
			AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`, ot, oid, r, st, sid, sr)
		key := TupleKey{User: openfgaUser(st, sid, sr), Relation: r, Object: ot + ":" + oid}
		if err := client.DeleteTupleSingle(ctx, storeID, key); err != nil {
			t.Fatalf("openfga delete %s:%s#%s @ %s: %v", ot, oid, r, key.User, err)
		}
	}
	checkBoth := func(t *testing.T, subj string, want bool) {
		t.Helper()
		engAllowed, err := en.Check(ctx, objType, objID, rel, "user", subj)
		if err != nil {
			t.Fatalf("engine check user:%s: %v", subj, err)
		}
		fgaAllowed, err := client.Check(ctx, storeID, modelID, TupleKey{User: "user:" + subj, Relation: rel, Object: objType + ":" + objID})
		if err != nil {
			t.Fatalf("openfga check user:%s: %v", subj, err)
		}
		if engAllowed != want || fgaAllowed != want {
			t.Fatalf("user:%s: engine=%v openfga=%v want=%v", subj, engAllowed, fgaAllowed, want)
		}
	}

	// tuple 3 (tier binding, this-leg direct to position#holder — the translator fix under test)
	writeBoth(t, objType, objID, rel, "position", posID, "holder")
	// member bridges for both candidate holders
	writeBoth(t, "member", memberA, "mapped_user", "user", userA, "")
	writeBoth(t, "member", memberB, "mapped_user", "user", userB, "")

	checkBoth(t, userA, false)
	checkBoth(t, userB, false)

	// grant: position:posID#holder @ member:memberA#mapped_user
	writeBoth(t, "position", posID, "holder", "member", memberA, "mapped_user")
	checkBoth(t, userA, true)
	checkBoth(t, userB, false)

	// revoke
	deleteBoth(t, "position", posID, "holder", "member", memberA, "mapped_user")
	checkBoth(t, userA, false)
	checkBoth(t, userB, false)

	// re-grant to a DIFFERENT member — replacement, both subjects checked
	writeBoth(t, "position", posID, "holder", "member", memberB, "mapped_user")
	checkBoth(t, userA, false)
	checkBoth(t, userB, true)
}

// TestHarnessGroupMutation is the differential proof for the `group` base type,
// mirroring TestHarnessPositionMutation's shape exactly: a userset-typed direct assignment
// (group#member as a company_module tier's directly-assignable subject shape) round-trips
// through OpenFGA, and an add-member -> check -> remove-member -> check mutation sequence
// behaves identically in engine and OpenFGA (static vectors.json can't express membership
// mutation any more than it could express position replacement).
func TestHarnessGroupMutation(t *testing.T) {
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

	modelData, err := os.ReadFile(filepath.Join("..", "engine", "model.json"))
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := engine.LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	dslPath := "model.fga"
	fgaModelDoc, err := BuildOpenFGAModel(model, dslPath)
	if err != nil {
		t.Fatalf("BuildOpenFGAModel: %v", err)
	}

	storeID, err := client.CreateStore(ctx, "kiban-harness-group-mutation")
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	modelID, err := client.WriteAuthorizationModel(ctx, storeID, fgaModelDoc)
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}

	en := &engine.Engine{Pool: pool, Model: model}

	const (
		objType = "company_module"
		objID   = "harn-grp-c1/helpdesk"
		rel     = "editor"
		groupID = "harn-grp-g1"
		memberA = "harn-grp-mA"
		memberB = "harn-grp-mB"
		userA   = "harn-grp-uA"
		userB   = "harn-grp-uB"
	)

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-grp-%' OR subject_id LIKE 'harn-grp-%'`)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-grp-%' OR subject_id LIKE 'harn-grp-%'`)
	})

	writeBoth := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, ot, oid, r, st, sid, sr)
		key := TupleKey{User: openfgaUser(st, sid, sr), Relation: r, Object: ot + ":" + oid}
		if err := client.WriteTupleSingle(ctx, storeID, key); err != nil {
			t.Fatalf("openfga write %s:%s#%s @ %s: %v", ot, oid, r, key.User, err)
		}
	}
	deleteBoth := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_type=$1 AND object_id=$2 AND relation=$3
			AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`, ot, oid, r, st, sid, sr)
		key := TupleKey{User: openfgaUser(st, sid, sr), Relation: r, Object: ot + ":" + oid}
		if err := client.DeleteTupleSingle(ctx, storeID, key); err != nil {
			t.Fatalf("openfga delete %s:%s#%s @ %s: %v", ot, oid, r, key.User, err)
		}
	}
	checkBoth := func(t *testing.T, subj string, want bool) {
		t.Helper()
		engAllowed, err := en.Check(ctx, objType, objID, rel, "user", subj)
		if err != nil {
			t.Fatalf("engine check user:%s: %v", subj, err)
		}
		fgaAllowed, err := client.Check(ctx, storeID, modelID, TupleKey{User: "user:" + subj, Relation: rel, Object: objType + ":" + objID})
		if err != nil {
			t.Fatalf("openfga check user:%s: %v", subj, err)
		}
		if engAllowed != want || fgaAllowed != want {
			t.Fatalf("user:%s: engine=%v openfga=%v want=%v", subj, engAllowed, fgaAllowed, want)
		}
	}

	// tuple 3 (tier binding, this-leg direct to group#member — the base-type addition under test)
	writeBoth(t, objType, objID, rel, "group", groupID, "member")
	// member bridges for both candidate group members
	writeBoth(t, "member", memberA, "mapped_user", "user", userA, "")
	writeBoth(t, "member", memberB, "mapped_user", "user", userB, "")

	checkBoth(t, userA, false)
	checkBoth(t, userB, false)

	// add member A to the group: group:groupID#member @ member:memberA#mapped_user
	writeBoth(t, "group", groupID, "member", "member", memberA, "mapped_user")
	checkBoth(t, userA, true)
	checkBoth(t, userB, false)

	// add member B too — groups hold multiple members simultaneously (unlike position#holder)
	writeBoth(t, "group", groupID, "member", "member", memberB, "mapped_user")
	checkBoth(t, userA, true)
	checkBoth(t, userB, true)

	// remove member A
	deleteBoth(t, "group", groupID, "member", "member", memberA, "mapped_user")
	checkBoth(t, userA, false)
	checkBoth(t, userB, true)

	// remove member B
	deleteBoth(t, "group", groupID, "member", "member", memberB, "mapped_user")
	checkBoth(t, userA, false)
	checkBoth(t, userB, false)
}

// TestHarnessCycle is the differential proof for tuple cycles: the
// shipped DSL admits no self-referential userset bracket, so this runs a two-type model —
// `group#member: [user, group#member]` — in its own store. A cycle `a#member @ b#member`,
// `b#member @ a#member` must answer false for an outsider and true for a direct member of `a`
// checked on `b`, in engine and OpenFGA alike; the engine must never turn the cycle into
// DEPTH_EXCEEDED.
func TestHarnessCycle(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping (see TestHarness's own skip message)")
	}

	ctx := context.Background()
	baseURL, stop, err := StartOpenFGA(ctx, 28086, 28087)
	if err != nil {
		t.Fatalf("start openfga container: %v", err)
	}
	t.Cleanup(stop)
	client := NewClient(baseURL)
	pool := authzPool(t)

	model, err := engine.LoadModel([]byte(`{"group": {"member": {"this": true}}}`))
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	fgaModelDoc := fgaModel{SchemaVersion: "1.1", TypeDefinitions: []fgaTypeDef{
		{Type: "user"},
		{Type: "group", Relations: map[string]fgaUserset{"member": {This: &struct{}{}}},
			Metadata: &fgaMetadata{Relations: map[string]fgaRelMetadata{"member": {DirectlyRelatedUserTypes: []fgaRelRef{{Type: "user"}, {Type: "group", Relation: "member"}}}}}},
	}}
	storeID, err := client.CreateStore(ctx, "kiban-harness-cycle")
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	modelID, err := client.WriteAuthorizationModel(ctx, storeID, fgaModelDoc)
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: model}

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-cyc-%' OR subject_id LIKE 'harn-cyc-%'`)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id LIKE 'harn-cyc-%' OR subject_id LIKE 'harn-cyc-%'`)
	})
	for _, tp := range [][6]string{
		{"group", "harn-cyc-a", "member", "group", "harn-cyc-b", "member"},
		{"group", "harn-cyc-b", "member", "group", "harn-cyc-a", "member"},
		{"group", "harn-cyc-a", "member", "user", "harn-cyc-in-a", ""},
	} {
		mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, tp[0], tp[1], tp[2], tp[3], tp[4], tp[5])
		if err := client.WriteTupleSingle(ctx, storeID, TupleKey{User: openfgaUser(tp[3], tp[4], tp[5]), Relation: tp[2], Object: tp[0] + ":" + tp[1]}); err != nil {
			t.Fatalf("openfga write %v: %v", tp, err)
		}
	}

	for _, c := range []struct {
		subj string
		want bool
	}{{"harn-cyc-nobody", false}, {"harn-cyc-in-a", true}} {
		engAllowed, err := en.Check(ctx, "group", "harn-cyc-b", "member", "user", c.subj)
		if err != nil {
			t.Fatalf("engine check user:%s on the cycle: %v (a plain cycle must never error)", c.subj, err)
		}
		fgaAllowed, err := client.Check(ctx, storeID, modelID, TupleKey{User: "user:" + c.subj, Relation: "member", Object: "group:harn-cyc-b"})
		if err != nil {
			t.Fatalf("openfga check user:%s: %v", c.subj, err)
		}
		if engAllowed != c.want || fgaAllowed != c.want {
			t.Fatalf("user:%s on group:harn-cyc-b#member: engine=%v openfga=%v want=%v", c.subj, engAllowed, fgaAllowed, c.want)
		}
		t.Logf("cycle check user:%s: engine=%v openfga=%v", c.subj, engAllowed, fgaAllowed)
	}
}

func loadPostgresRows(ctx context.Context, pool *pgxpool.Pool, rows [][6]string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	copyRows := make([][]any, len(rows))
	for i, r := range rows {
		copyRows[i] = []any{r[0], r[1], r[2], r[3], r[4], r[5]}
	}
	_, err = conn.Conn().CopyFrom(ctx, pgx.Identifier{"authz", "tuple"},
		[]string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"},
		pgx.CopyFromRows(copyRows))
	return err
}

func loadOpenFGARows(ctx context.Context, client *Client, storeID string, rows [][6]string) error {
	keys := make([]TupleKey, len(rows))
	for i, r := range rows {
		keys[i] = TupleKey{User: openfgaUser(r[3], r[4], r[5]), Relation: r[2], Object: r[0] + ":" + r[1]}
	}
	return client.WriteTuples(ctx, storeID, keys)
}
