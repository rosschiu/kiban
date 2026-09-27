// SPDX-License-Identifier: Apache-2.0

// Package audit is the platform's ONE audit writer: every service
// writes its own audit.<module>__* table through this package instead of hand-rolling INSERT
// statements per service. Record must be called inside the SAME transaction as the state
// change it documents (atomicity) — it takes a pgx.Tx, never a pool.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/obs"
)

// tableNamePattern is deliberately strict: audit tables are named audit.<module>__<name>.
// The table name is never accepted
// from a request; only from code that constructs a Writer at startup, but it is still
// validated here so a typo fails loudly instead of building an injectable query string.
var tableNamePattern = regexp.MustCompile(`^audit\.[a-z][a-z0-9]*__[a-z][a-z0-9_]*$`)

// Event is one audit record. Actor MUST be derived server-side from the validated auth
// context — never from a request body. Payload is marshaled to JSON as-is; nil
// becomes an empty object. CorrelationID left empty is filled from ctx (the id
// httpx.Correlation stored there), so a handler that passes its request context through to
// Record gets the row joined to its request for free.
type Event struct {
	Actor         string
	Action        string
	Subject       string
	Payload       map[string]any
	CorrelationID string
}

// Tx is the subset of pgx.Tx that Record needs (structurally satisfied by *pgx.Tx and by
// sqlc's generated DBTX-backed transactions — no adapter required).
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Writer records events to one fixed, validated audit table.
type Writer struct {
	insertSQL string
}

// NewWriter builds a Writer for the given fully-qualified audit table name
// (e.g. "audit.registry__events"). It returns an error if the name doesn't match the
// audit.<module>__<name> convention.
func NewWriter(table string) (*Writer, error) {
	if !tableNamePattern.MatchString(table) {
		return nil, fmt.Errorf("audit: invalid table name %q: must match audit.<module>__<name>", table)
	}
	return &Writer{
		insertSQL: fmt.Sprintf(
			"INSERT INTO %s (actor, action, subject, payload, correlation_id) VALUES ($1, $2, $3, $4, $5)",
			table,
		),
	}, nil
}

// Record writes ev to the writer's table using tx — the caller's transaction, so the audit
// row commits or rolls back atomically with the state change it documents. An empty
// ev.CorrelationID is taken from ctx (see Event).
func (w *Writer) Record(ctx context.Context, tx Tx, ev Event) error {
	payload := ev.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("audit: marshal payload: %w", err)
	}

	if ev.CorrelationID == "" {
		ev.CorrelationID, _ = obs.CorrelationFromContext(ctx)
	}
	var correlationID *string
	if ev.CorrelationID != "" {
		correlationID = &ev.CorrelationID
	}

	_, err = tx.Exec(ctx, w.insertSQL, ev.Actor, ev.Action, ev.Subject, b, correlationID)
	if err != nil {
		return fmt.Errorf("audit: record event: %w", err)
	}
	return nil
}

// Denial best-effort records an authorization denial in its own transaction (denials are
// audited too). reason is the payload's `reason`: authz's own decision reason for a confirmed
// denial (403), or "AUTHORIZATION_UNAVAILABLE" when no definite answer was reached (503). A
// failure to write the denial row must not mask the response the caller already gets — it's
// logged nowhere here (the services have no logger wired in); the httpx.Recover middleware and
// access log still cover operational visibility.
func Denial(ctx context.Context, pool *pgxpool.Pool, w *Writer, actor, action, subject, reason string) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := w.Record(ctx, tx, Event{
		Actor:   actor,
		Action:  action,
		Subject: subject,
		Payload: map[string]any{"denied": true, "reason": reason},
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}
