// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rosschiu/kiban/internal/obs"
)

// BEHAVIORAL tests for audit.go: NewWriter's table-name validation (every table this package's callers actually use, plus
// the invalid shapes the regex must reject), Record's in-transaction commit/rollback semantics
// against the real live Postgres dev stack (audit.identity__events — Postgres is never mocked,
// so this is a real driver round trip),
// its payload-default/marshal-error/correlation-id branches, and actor round-tripping (this
// package never derives or mutates Actor itself — that's every caller's own job, e.g.
// internal/identity/http.go's actorFor — so the proof here is that Record stores exactly the
// actor string it's given, unmodified, including edge-case values like "unauthenticated").

func TestNewWriter_ValidTableNames(t *testing.T) {
	valid := []string{
		"audit.identity__events",
		"audit.authz__events",
		"audit.org__events",
		"audit.registry__events",
		"audit.a__b",
		"audit.mod1__thing_two",
	}
	for _, table := range valid {
		t.Run(table, func(t *testing.T) {
			w, err := NewWriter(table)
			if err != nil {
				t.Fatalf("NewWriter(%q): unexpected error: %v", table, err)
			}
			if w == nil {
				t.Fatal("expected a non-nil Writer")
			}
		})
	}
}

func TestNewWriter_InvalidTableNames(t *testing.T) {
	invalid := []string{
		"",
		"identity__events",             // missing audit. prefix
		"audit.identity_events",        // single underscore, not double
		"audit.Identity__events",       // uppercase
		"audit.1identity__events",      // starts with a digit
		"audit.identity__",             // empty name after __
		"audit.__events",               // empty module before __
		"audit.identity__events; DROP", // not a bare identifier
		"other.identity__events",       // wrong schema
		"audit.identity__Events",       // uppercase in name part
	}
	for _, table := range invalid {
		t.Run(table, func(t *testing.T) {
			if _, err := NewWriter(table); err == nil {
				t.Fatalf("NewWriter(%q): expected an error, got none", table)
			}
		})
	}
}

// fakeTx is a minimal Tx double used ONLY to prove Record's own Go-level branching (payload-nil
// default, correlation-id nil-vs-set, marshal-error short-circuit, Exec-error propagation) —
// argument-capturing logic, not a stand-in for Postgres's own transactional behavior (that's
// proven separately below against the real live stack: Postgres itself is never mocked here).
type fakeTx struct {
	gotSQL  string
	gotArgs []any
	execErr error
	called  bool
}

func (f *fakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.called = true
	f.gotSQL = sql
	f.gotArgs = args
	if f.execErr != nil {
		return pgconn.CommandTag{}, f.execErr
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestRecord_NilPayloadBecomesEmptyJSONObject(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	tx := &fakeTx{}
	if err := w.Record(context.Background(), tx, Event{Actor: "a", Action: "act", Subject: "subj"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if !tx.called {
		t.Fatal("expected Exec to be called")
	}
	if len(tx.gotArgs) != 5 {
		t.Fatalf("expected 5 args (actor, action, subject, payload, correlation_id), got %d: %v", len(tx.gotArgs), tx.gotArgs)
	}
	payload, ok := tx.gotArgs[3].([]byte)
	if !ok {
		t.Fatalf("expected the payload arg to be []byte, got %T", tx.gotArgs[3])
	}
	if string(payload) != "{}" {
		t.Fatalf("expected a nil payload to marshal to an empty object, got %q", string(payload))
	}
}

func TestRecord_CorrelationIDBranches(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	t.Run("empty correlation id becomes nil", func(t *testing.T) {
		tx := &fakeTx{}
		if err := w.Record(context.Background(), tx, Event{Actor: "a", Action: "act", Subject: "s"}); err != nil {
			t.Fatalf("record: %v", err)
		}
		ptr, ok := tx.gotArgs[4].(*string)
		if !ok {
			t.Fatalf("expected a *string correlation_id arg, got %T", tx.gotArgs[4])
		}
		if ptr != nil {
			t.Fatalf("expected a nil correlation_id arg for an empty CorrelationID, got %v", *ptr)
		}
	})

	t.Run("set correlation id is passed through as a pointer to its value", func(t *testing.T) {
		tx := &fakeTx{}
		if err := w.Record(context.Background(), tx, Event{Actor: "a", Action: "act", Subject: "s", CorrelationID: "corr-123"}); err != nil {
			t.Fatalf("record: %v", err)
		}
		ptr, ok := tx.gotArgs[4].(*string)
		if !ok || ptr == nil {
			t.Fatalf("expected a non-nil *string correlation_id arg, got %T(%v)", tx.gotArgs[4], tx.gotArgs[4])
		}
		if *ptr != "corr-123" {
			t.Fatalf("correlation id = %q, want %q", *ptr, "corr-123")
		}
	})

	t.Run("empty correlation id is taken from the context; an explicit one wins", func(t *testing.T) {
		ctx := obs.ContextWithCorrelation(context.Background(), "corr-ctx")
		tx := &fakeTx{}
		if err := w.Record(ctx, tx, Event{Actor: "a", Action: "act", Subject: "s"}); err != nil {
			t.Fatalf("record: %v", err)
		}
		if ptr, _ := tx.gotArgs[4].(*string); ptr == nil || *ptr != "corr-ctx" {
			t.Fatalf("correlation id from ctx = %v, want corr-ctx", tx.gotArgs[4])
		}
		tx = &fakeTx{}
		if err := w.Record(ctx, tx, Event{Actor: "a", Action: "act", Subject: "s", CorrelationID: "corr-explicit"}); err != nil {
			t.Fatalf("record: %v", err)
		}
		if ptr, _ := tx.gotArgs[4].(*string); ptr == nil || *ptr != "corr-explicit" {
			t.Fatalf("explicit correlation id = %v, want corr-explicit", tx.gotArgs[4])
		}
	})
}

func TestRecord_ActorActionSubjectRoundTripExactly(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	tx := &fakeTx{}
	ev := Event{Actor: "unauthenticated", Action: "identity.platform_role.grant", Subject: "user:abc-123"}
	if err := w.Record(context.Background(), tx, ev); err != nil {
		t.Fatalf("record: %v", err)
	}
	if tx.gotArgs[0] != ev.Actor {
		t.Fatalf("actor arg = %v, want %q (Record must never derive/rewrite Actor itself)", tx.gotArgs[0], ev.Actor)
	}
	if tx.gotArgs[1] != ev.Action {
		t.Fatalf("action arg = %v, want %q", tx.gotArgs[1], ev.Action)
	}
	if tx.gotArgs[2] != ev.Subject {
		t.Fatalf("subject arg = %v, want %q", tx.gotArgs[2], ev.Subject)
	}
}

func TestRecord_PayloadMarshaled(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	tx := &fakeTx{}
	ev := Event{Actor: "a", Action: "act", Subject: "s", Payload: map[string]any{"role": "kiban-superadmin", "denied": true}}
	if err := w.Record(context.Background(), tx, ev); err != nil {
		t.Fatalf("record: %v", err)
	}
	payload, ok := tx.gotArgs[3].([]byte)
	if !ok {
		t.Fatalf("expected []byte payload arg, got %T", tx.gotArgs[3])
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode marshaled payload: %v", err)
	}
	if decoded["role"] != "kiban-superadmin" || decoded["denied"] != true {
		t.Fatalf("payload not marshaled faithfully: %v", decoded)
	}
}

// TestRecord_MarshalErrorNeverCallsExec covers Record's json.Marshal error branch: a channel
// value can never be marshaled to JSON. The fakeTx asserts Exec is never reached — the marshal
// failure must short-circuit before any write is attempted.
func TestRecord_MarshalErrorNeverCallsExec(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	tx := &fakeTx{}
	ev := Event{Actor: "a", Action: "act", Subject: "s", Payload: map[string]any{"bad": make(chan int)}}
	if err := w.Record(context.Background(), tx, ev); err == nil {
		t.Fatal("expected an error for an unmarshalable payload")
	}
	if tx.called {
		t.Fatal("expected Exec to never be called when payload marshaling fails")
	}
}

// TestRecord_ExecErrorPropagates covers Record's own Exec-error wrapping branch.
func TestRecord_ExecErrorPropagates(t *testing.T) {
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	wantErr := errors.New("boom: constraint violation")
	tx := &fakeTx{execErr: wantErr}
	err = w.Record(context.Background(), tx, Event{Actor: "a", Action: "act", Subject: "s"})
	if err == nil {
		t.Fatal("expected the Exec error to propagate")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the wrapped error to unwrap to the Exec error, got %v", err)
	}
}

// --- live-Postgres in-transaction semantics (Postgres itself is never mocked) ---

func TestRecord_CommitPersistsTheRow(t *testing.T) {
	admin := adminPool(t)
	resetAuditFixtures(t, admin)
	pool := identityPool(t)
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := w.Record(ctx, tx, Event{
		Actor: "test-actor", Action: "test.commit", Subject: "subject:1",
		Payload: map[string]any{"k": "v"}, CorrelationID: "corr-commit",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var actor, action, subject, correlationID string
	var payload []byte
	err = admin.QueryRow(ctx, `
		SELECT actor, action, subject, payload, correlation_id FROM audit.identity__events
		WHERE action = 'test.commit'
	`).Scan(&actor, &action, &subject, &payload, &correlationID)
	if err != nil {
		t.Fatalf("query committed row: %v", err)
	}
	if actor != "test-actor" || action != "test.commit" || subject != "subject:1" || correlationID != "corr-commit" {
		t.Fatalf("unexpected committed row: actor=%q action=%q subject=%q correlation_id=%q", actor, action, subject, correlationID)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded["k"] != "v" {
		t.Fatalf("unexpected payload: %v", decoded)
	}
}

// TestRecord_RollbackDoesNotPersist is the other half of the in-transaction-atomicity proof
// a Record'd event inside a transaction that gets rolled back must leave no trace —
// exactly the guarantee every caller relies on when it writes its own state change and the audit
// row in the SAME transaction.
func TestRecord_RollbackDoesNotPersist(t *testing.T) {
	admin := adminPool(t)
	resetAuditFixtures(t, admin)
	pool := identityPool(t)
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := w.Record(ctx, tx, Event{Actor: "test-actor", Action: "test.rollback", Subject: "subject:2"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit.identity__events WHERE action = 'test.rollback'`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected the rolled-back Record to leave no row, found %d", count)
	}
}

// TestRecord_RealPostgresExecErrorPropagates covers Record's Exec-error branch against a REAL
// Postgres error (not the fakeTx double above): a NUL byte is syntactically a valid Go string
// but not valid Postgres text (UTF8 forbids embedded NULs), so the INSERT genuinely fails at the
// database.
func TestRecord_RealPostgresExecErrorPropagates(t *testing.T) {
	admin := adminPool(t)
	resetAuditFixtures(t, admin)
	pool := identityPool(t)
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after this test's own explicit handling

	err = w.Record(ctx, tx, Event{Actor: "bad\x00actor", Action: "test.execerr", Subject: "s"})
	if err == nil {
		t.Fatal("expected a real Postgres error for a NUL-byte actor value")
	}
}

// TestDenial covers the best-effort denial row: it commits on its own transaction, and both
// failure branches (pool Begin, Record) return silently without a row.
func TestDenial_CommitsOwnTransaction(t *testing.T) {
	admin := adminPool(t)
	resetAuditFixtures(t, admin)
	pool := identityPool(t)
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	Denial(context.Background(), pool, w, "kc-actor", "test.denial", "subject:9", "PLATFORM_ROLE_REQUIRED")

	var actor, subject string
	var payload []byte
	err = admin.QueryRow(context.Background(), `
		SELECT actor, subject, payload FROM audit.identity__events WHERE action = 'test.denial'
	`).Scan(&actor, &subject, &payload)
	if err != nil {
		t.Fatalf("query denial row: %v", err)
	}
	if actor != "kc-actor" || subject != "subject:9" {
		t.Fatalf("unexpected denial row: actor=%q subject=%q", actor, subject)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded["denied"] != true || decoded["reason"] != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("unexpected payload: %v", decoded)
	}
}

func TestDenial_FailuresLeaveNoRow(t *testing.T) {
	admin := adminPool(t)
	resetAuditFixtures(t, admin)
	pool := identityPool(t)
	w, err := NewWriter("audit.identity__events")
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	// Record error: a table the identity role has no rights on.
	missing, _ := NewWriter("audit.identity__missing")
	Denial(context.Background(), pool, missing, "kc-actor", "test.denial.record", "subject:9", "AUTHORIZATION_UNAVAILABLE")

	// Begin error: a closed pool.
	closed := identityPool(t)
	closed.Close()
	Denial(context.Background(), closed, w, "kc-actor", "test.denial.begin", "subject:9", "AUTHORIZATION_UNAVAILABLE")

	var n int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM audit.identity__events`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 0 {
		t.Fatalf("rows = %d, want 0 after two failed denials", n)
	}
}
