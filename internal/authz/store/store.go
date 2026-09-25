// SPDX-License-Identifier: Apache-2.0

// Package store is the transactional grant API: Grant/Revoke are small exported helpers
// usable inside a CALLER's own transaction (a pgx.Tx parameter), so another service (e.g. org
// creating a position) can write its business row and the matching authz tuple atomically, in
// one commit. No sqlc codegen here — the statements are simple fixed shapes, consistent with
// internal/authz/engine's own raw-SQL fetchRows.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The platform role has exactly one record: the tuple `system:platform#superadmin @ user:<kcSub>`
// (SystemPlatformID, default_grant.go, is the `system` object). PlatformRoleSuperadmin is the
// only platform role name.
const PlatformRoleSuperadmin = "kiban-superadmin"

// SuperadminTuple is the one tuple that makes subjectID (a kcSub) the platform superadmin.
func SuperadminTuple(subjectID string) Tuple {
	return Tuple{ObjectType: "system", ObjectID: SystemPlatformID, Relation: "superadmin", SubjectType: "user", SubjectID: subjectID}
}

const countSuperadminsSQL = `
SELECT count(*) FROM authz.tuple
WHERE object_type = 'system' AND object_id = '` + SystemPlatformID + `' AND relation = 'superadmin'
  AND subject_type = 'user' AND subject_relation = ''`

// Rower is the minimal single-row read interface CountSuperadmins needs — satisfied by
// *pgxpool.Pool and pgx.Tx alike (same stance as Queryer below).
type Rower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// CountSuperadmins counts the direct `system:platform#superadmin` tuples — bootstrap's
// one-time-creation marker and the last-superadmin guard's input (run it inside the revoking
// transaction, under the advisory lock the HTTP handler takes, for the latter).
func CountSuperadmins(ctx context.Context, q Rower) (int, error) {
	var n int
	if err := q.QueryRow(ctx, countSuperadminsSQL).Scan(&n); err != nil {
		return 0, fmt.Errorf("authz/store: count superadmins: %w", err)
	}
	return n, nil
}

// Tuple is one authz.tuple row shape (object-id encoding is "type:id" at the API boundary;
// the four/five raw columns here are the storage shape).
type Tuple struct {
	ObjectType      string
	ObjectID        string
	Relation        string
	SubjectType     string
	SubjectID       string
	SubjectRelation string // "" = direct subject; else userset subject ("type:id#relation")
}

const insertTupleSQL = `
INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING`

const deleteTupleSQL = `
DELETE FROM authz.tuple
WHERE object_type = $1 AND object_id = $2 AND relation = $3
  AND subject_type = $4 AND subject_id = $5 AND subject_relation = $6`

const insertLedgerSQL = `
INSERT INTO authz.grant_ledger
  (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

// Grant writes tuples into authz.tuple and records each in authz.grant_ledger, using tx — the
// caller's own transaction. It never begins or commits a transaction itself: that is the
// caller's responsibility, which is exactly what lets a business-write-plus-grant commit or
// roll back as one unit. actor must be the validated bearer subject (never a body-supplied
// value); correlationID may be empty.
func Grant(ctx context.Context, tx pgx.Tx, actor, correlationID string, tuples ...Tuple) error {
	return writeTuples(ctx, tx, actor, correlationID, "grant", tuples)
}

// Revoke deletes tuples from authz.tuple and records each in authz.grant_ledger, using tx —
// the caller's own transaction. Deleting a tuple that doesn't exist is a no-op (idempotent),
// still ledgered.
func Revoke(ctx context.Context, tx pgx.Tx, actor, correlationID string, tuples ...Tuple) error {
	return writeTuples(ctx, tx, actor, correlationID, "revoke", tuples)
}

// Queryer is the minimal read interface ListDirectTuplesForSubject needs — satisfied by both
// *pgxpool.Pool (a plain read outside any transaction, the summary composition's use case) and
// pgx.Tx, without this package importing pgxpool (it stays pool-shape-agnostic, matching
// Grant/Revoke's own tx-only stance above).
type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const listDirectTuplesForSubjectSQL = `
SELECT object_type, object_id, relation
FROM authz.tuple
WHERE subject_type = $1 AND subject_id = $2 AND subject_relation = ''
ORDER BY object_type, object_id, relation`

// ObjectRelation is one (objectType, objectId, relation) direct grant.
type ObjectRelation struct {
	ObjectType string
	ObjectID   string
	Relation   string
}

// ListDirectTuplesForSubject reads every DIRECT tuple (empty subject_relation, i.e. a plain
// subject — never a userset expansion) naming subjectType:subjectID as the subject — the raw
// material for the effective-access summary's `objectAccess` field. This is a direct-grant
// listing, not a closure/expansion of what the subject can reach via role/userset membership —
// the summary is a display aid, not an enforcement surface, and enforcement itself never runs
// off any cached or precomputed listing.
func ListDirectTuplesForSubject(ctx context.Context, q Queryer, subjectType, subjectID string) ([]ObjectRelation, error) {
	rows, err := q.Query(ctx, listDirectTuplesForSubjectSQL, subjectType, subjectID)
	if err != nil {
		return nil, fmt.Errorf("authz/store: list direct tuples for subject: %w", err)
	}
	defer rows.Close()
	var out []ObjectRelation
	for rows.Next() {
		var r ObjectRelation
		if err := rows.Scan(&r.ObjectType, &r.ObjectID, &r.Relation); err != nil {
			return nil, fmt.Errorf("authz/store: scan tuple row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz/store: iterate tuple rows: %w", err)
	}
	return out, nil
}

func writeTuples(ctx context.Context, tx pgx.Tx, actor, correlationID, op string, tuples []Tuple) error {
	if len(tuples) == 0 {
		return fmt.Errorf("authz/store: %s requires at least one tuple", op)
	}
	var corrID any
	if correlationID != "" {
		corrID = correlationID
	}
	for _, tp := range tuples {
		if tp.ObjectType == "" || tp.ObjectID == "" || tp.Relation == "" || tp.SubjectType == "" || tp.SubjectID == "" {
			return fmt.Errorf("authz/store: %s: tuple has an empty required field: %+v", op, tp)
		}
		switch op {
		case "grant":
			if _, err := tx.Exec(ctx, insertTupleSQL,
				tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
			); err != nil {
				return fmt.Errorf("authz/store: insert tuple: %w", err)
			}
		case "revoke":
			if _, err := tx.Exec(ctx, deleteTupleSQL,
				tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
			); err != nil {
				return fmt.Errorf("authz/store: delete tuple: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, insertLedgerSQL,
			actor, tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation, op, corrID,
		); err != nil {
			return fmt.Errorf("authz/store: insert grant_ledger row: %w", err)
		}
	}
	return nil
}
