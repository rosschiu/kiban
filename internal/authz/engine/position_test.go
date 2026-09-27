// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"testing"
)

// TestPositionEngine is the engine-level proof of the three-tuple position design:
// position:<id>#holder @ member:<id>#mapped_user, member:<id>#mapped_user @
// user:<kcSub>, and a company_module tier (editor, the helpdesk agent tier) directly assignable
// to position#holder. It also covers the replacement/mutation shape
// (grant -> check -> revoke -> re-grant to a DIFFERENT member -> check both subjects), since the
// static vectors.json floor can't express "the same position now resolves to someone else".
func TestPositionEngine(t *testing.T) {
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
	eng := &Engine{Pool: pool, Model: model}

	const (
		objType = "company_module"
		objID   = "pos-eng-c1/helpdesk"
		rel     = "editor"
		posID   = "pos-eng-p1"
		memberA = "pos-eng-mA"
		memberB = "pos-eng-mB"
		userA   = "pos-eng-uA"
		userB   = "pos-eng-uB"
	)

	clear := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'pos-eng-%' OR subject_id LIKE 'pos-eng-%'`); err != nil {
			t.Fatalf("clear pos-eng- fixture: %v", err)
		}
	}
	clear(t)
	t.Cleanup(func() { clear(t) })

	insert := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			ot, oid, r, st, sid, sr,
		); err != nil {
			t.Fatalf("insert tuple %s:%s#%s @ %s:%s#%s: %v", ot, oid, r, st, sid, sr, err)
		}
	}
	del := func(t *testing.T, ot, oid, r, st, sid, sr string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`DELETE FROM authz.tuple WHERE object_type=$1 AND object_id=$2 AND relation=$3
			 AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`,
			ot, oid, r, st, sid, sr,
		); err != nil {
			t.Fatalf("delete tuple %s:%s#%s @ %s:%s#%s: %v", ot, oid, r, st, sid, sr, err)
		}
	}
	mustCheck := func(t *testing.T, subj string, want bool) {
		t.Helper()
		allowed, err := eng.Check(ctx, objType, objID, rel, "user", subj)
		if err != nil {
			t.Fatalf("check user:%s: unexpected error: %v", subj, err)
		}
		if allowed != want {
			t.Fatalf("check user:%s: allowed=%v want=%v", subj, allowed, want)
		}
	}

	// tuple 3: the tier binding, direct to position#holder (never a userset itself)
	insert(t, objType, objID, rel, "position", posID, "holder")
	// tuple 2: member-bridge
	insert(t, "member", memberA, "mapped_user", "user", userA, "")

	t.Run("no holder tuple yet: deny", func(t *testing.T) {
		mustCheck(t, userA, false)
	})

	// tuple 1: the position assignment (org-owned; written directly here for the engine proof)
	insert(t, "position", posID, "holder", "member", memberA, "mapped_user")

	t.Run("grant: holder resolves through the triangle", func(t *testing.T) {
		mustCheck(t, userA, true)
	})

	t.Run("revoke: end assignment denies", func(t *testing.T) {
		del(t, "position", posID, "holder", "member", memberA, "mapped_user")
		mustCheck(t, userA, false)
	})

	t.Run("re-grant to a different member: replacement, not accumulation", func(t *testing.T) {
		insert(t, "member", memberB, "mapped_user", "user", userB, "")
		insert(t, "position", posID, "holder", "member", memberB, "mapped_user")
		mustCheck(t, userB, true)
		mustCheck(t, userA, false) // A's holder tuple stays revoked — no stale access
	})
}
