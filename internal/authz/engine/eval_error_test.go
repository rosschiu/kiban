// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestCheckErrorMessage covers CheckError.Error()'s formatting (Code + ": " + Msg) via a real
// fail-closed UNKNOWN_TYPE outcome from Check.
func TestCheckErrorMessage(t *testing.T) {
	modelData, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	eng := &Engine{Pool: authzPool(t), Model: model}

	_, err = eng.Check(context.Background(), "nonexistent_type", "x", "y", "user", "z")
	if err == nil {
		t.Fatal("want error for unknown type, got nil")
	}
	ce, ok := err.(*CheckError)
	if !ok {
		t.Fatalf("want *CheckError, got %T", err)
	}
	if got, want := ce.Error(), "UNKNOWN_TYPE: "+ce.Msg; got != want {
		t.Fatalf("CheckError.Error() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(ce.Error(), "UNKNOWN_TYPE: ") {
		t.Fatalf("CheckError.Error() = %q, want prefix %q", ce.Error(), "UNKNOWN_TYPE: ")
	}
}

// TestFetchRowsQueryErrorPropagation exercises the fetchRows query-failure path (eval.go's
// `query tuple rows: %w` wrap) and both of its call-site propagation checks — evalThis (a
// relation resolved via the "this" construct) and evalTupleToUserset (a relation resolved via
// tupleToUserset) — by pre-canceling the context so the very first pgx query pgx issues fails
// deterministically. This is a real Postgres/pgx behavior (context cancellation), not a mock
// (mocks only for genuinely external systems).
func TestFetchRowsQueryErrorPropagation(t *testing.T) {
	modelData, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	eng := &Engine{Pool: authzPool(t), Model: model}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("via evalThis (company#admin resolves through the this construct first)", func(t *testing.T) {
		_, err := eng.Check(canceledCtx, "company", "errtest-c1", "admin", "user", "errtest-u1")
		if err == nil {
			t.Fatal("want a query error from a pre-canceled context, got nil")
		}
		if !strings.Contains(err.Error(), "query tuple rows") {
			t.Fatalf("want error wrapping fetchRows' \"query tuple rows\" message, got: %v", err)
		}
		if _, ok := err.(*CheckError); ok {
			t.Fatalf("a raw DB error must propagate as-is, not disguised as a *CheckError: %v", err)
		}
	})

	t.Run("via evalTupleToUserset (member_directory#admin is TWO tupleToUserset children, no this)", func(t *testing.T) {
		_, err := eng.Check(canceledCtx, "member_directory", "errtest-md1", "admin", "user", "errtest-u1")
		if err == nil {
			t.Fatal("want a query error from a pre-canceled context, got nil")
		}
		if !strings.Contains(err.Error(), "query tuple rows") {
			t.Fatalf("want error wrapping fetchRows' \"query tuple rows\" message, got: %v", err)
		}
	})
}

// TestTupleToUsersetSkipsUsersetSubjectRows and TestTupleToUsersetPropagatesRecursiveCheckError
// cover evalTupleToUserset's two remaining branches: skipping a userset-valued subject row on
// the tupleset relation (outside the subset's tupleToUserset shape, per the fail-closed comment
// in eval.go), and propagating an error raised by the recursive check() call.
func TestTupleToUsersetSkipsUsersetSubjectRows(t *testing.T) {
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

	if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'ttuskip-%' OR subject_id LIKE 'ttuskip-%'`); err != nil {
		t.Fatalf("clear ttuskip- fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'ttuskip-%' OR subject_id LIKE 'ttuskip-%'`)
	})

	// member_directory#admin = union[ tupleToUserset(company_module,admin), tupleToUserset(system,superadmin) ].
	// Insert a company_module-tupleset row that is itself userset-valued (subject_relation set) —
	// outside the subset's tupleToUserset shape — plus a real system/superadmin grant so the
	// overall check still resolves true via the SECOND union child, proving the skip didn't
	// silently break the rest of evaluation.
	batch := &pgx.Batch{}
	batch.Queue(
		`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
		 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		"member_directory", "ttuskip-md1", "company_module", "company_module", "ttuskip-cm1", "admin", // userset-valued tupleset row: must be skipped
	)
	batch.Queue(
		`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
		 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		"system", "ttuskip-sys1", "superadmin", "user", "ttuskip-super", "",
	)
	batch.Queue(
		`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
		 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		"member_directory", "ttuskip-md1", "system", "system", "ttuskip-sys1", "",
	)
	br := pool.SendBatch(ctx, batch)
	for i := 0; i < 3; i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			t.Fatalf("insert fixture tuple %d: %v", i, err)
		}
	}
	if err := br.Close(); err != nil {
		t.Fatalf("close fixture batch: %v", err)
	}

	eng := &Engine{Pool: pool, Model: model}
	allowed, err := eng.Check(ctx, "member_directory", "ttuskip-md1", "admin", "user", "ttuskip-super")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("want allow via the system/superadmin union child; the userset-valued tupleset row must be skipped, not error or misinterpreted")
	}

	// A subject who is NOT the superadmin, and has no path through the (correctly skipped)
	// userset-valued row, must be denied — proves the skip doesn't accidentally grant access.
	denied, err := eng.Check(ctx, "member_directory", "ttuskip-md1", "admin", "user", "someone-else")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatal("want deny for a subject with no valid grant path")
	}
}

func TestTupleToUsersetPropagatesRecursiveCheckError(t *testing.T) {
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

	if _, err := pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE 'ttuerr-%' OR subject_id LIKE 'ttuerr-%'`); err != nil {
		t.Fatalf("clear ttuerr- fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'ttuerr-%' OR subject_id LIKE 'ttuerr-%'`)
	})

	// member_directory#admin's first union child is tupleToUserset(company_module,admin). Point
	// the company_module-tupleset row at a subject_type the model has no definition for, so the
	// recursive check() call inside evalTupleToUserset returns UNKNOWN_TYPE, and that error must
	// propagate out of evalTupleToUserset (not be swallowed as deny).
	if _, err := pool.Exec(ctx,
		`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
		 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		"member_directory", "ttuerr-md1", "company_module", "no_such_type_in_model", "ttuerr-x", "",
	); err != nil {
		t.Fatalf("insert fixture tuple: %v", err)
	}

	eng := &Engine{Pool: pool, Model: model}
	_, err = eng.Check(ctx, "member_directory", "ttuerr-md1", "admin", "user", "ttuerr-whoever")
	if err == nil {
		t.Fatal("want UNKNOWN_TYPE error to propagate from the recursive check() call, got nil")
	}
	ce, ok := err.(*CheckError)
	if !ok {
		t.Fatalf("want *CheckError, got %T: %v", err, err)
	}
	if ce.Code != "UNKNOWN_TYPE" {
		t.Fatalf("want UNKNOWN_TYPE, got %s (%v)", ce.Code, ce)
	}
}
