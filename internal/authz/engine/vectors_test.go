// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestVectors replays the vectors.json cases (the regression floor) against the product
// authz.tuple table.

type vectorTuple struct {
	ObjectType      string `json:"object_type"`
	ObjectID        string `json:"object_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation"`
}

type vector struct {
	Name            string `json:"name"`
	Why             string `json:"why"`
	ObjType         string `json:"objType"`
	ObjID           string `json:"objID"`
	Rel             string `json:"rel"`
	SubjType        string `json:"subjType"`
	SubjID          string `json:"subjID"`
	Expect          string `json:"expect"` // allow | deny | error
	ExpectErrorCode string `json:"expectErrorCode"`
}

type vectorFixture struct {
	Tuples  []vectorTuple `json:"tuples"`
	Vectors []vector      `json:"vectors"`
}

func TestVectors(t *testing.T) {
	ctx := context.Background()

	data, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var fixture vectorFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if len(fixture.Vectors) < 40 {
		t.Fatalf("vectors.json: spec requires >=40 cases, got %d", len(fixture.Vectors))
	}

	modelData, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	pool := authzPool(t)

	// Idempotent fixture load: only ever touches the 'vec-' namespace, safe to run regardless
	// of what else is in authz.tuple (e.g. the bench loadgen dataset, when both share a database).
	if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'vec-%' OR subject_id LIKE 'vec-%'`); err != nil {
		t.Fatalf("clear vec- fixture: %v", err)
	}
	batch := &pgx.Batch{}
	for _, tp := range fixture.Tuples {
		batch.Queue(
			`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
			 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
		)
	}
	br := pool.SendBatch(ctx, batch)
	for range fixture.Tuples {
		if _, err := br.Exec(); err != nil {
			br.Close()
			t.Fatalf("insert fixture tuple: %v", err)
		}
	}
	if err := br.Close(); err != nil {
		t.Fatalf("close fixture batch: %v", err)
	}

	eng := &Engine{Pool: pool, Model: model}

	for _, v := range fixture.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			allowed, err := eng.Check(ctx, v.ObjType, v.ObjID, v.Rel, v.SubjType, v.SubjID)
			switch v.Expect {
			case "allow":
				if err != nil {
					t.Fatalf("why=%q: unexpected error: %v", v.Why, err)
				}
				if !allowed {
					t.Fatalf("why=%q: want allow, got deny", v.Why)
				}
			case "deny":
				if err != nil {
					t.Fatalf("why=%q: unexpected error: %v", v.Why, err)
				}
				if allowed {
					t.Fatalf("why=%q: want deny, got allow", v.Why)
				}
			case "error":
				if err == nil {
					t.Fatalf("why=%q: want error %s, got no error (allowed=%v)", v.Why, v.ExpectErrorCode, allowed)
				}
				ce, ok := err.(*CheckError)
				if !ok {
					t.Fatalf("why=%q: want *CheckError, got %T: %v", v.Why, err, err)
				}
				if ce.Code != v.ExpectErrorCode {
					t.Fatalf("why=%q: want error code %s, got %s (%v)", v.Why, v.ExpectErrorCode, ce.Code, err)
				}
			default:
				t.Fatalf("vectors.json: vector %q has unknown expect %q", v.Name, v.Expect)
			}
			t.Logf("why: %s", v.Why)
		})
	}
}
