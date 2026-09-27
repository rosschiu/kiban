// SPDX-License-Identifier: Apache-2.0

// The caller-facing half of the SECURITY DEFINER revocation path.
// org's runtime role (kiban_org) has no DELETE grant on authz.tuple at all — see
// migrations/authz/0006_position_holder_revoke.sql for the function this wraps and the rationale.
// RevokePositionOrMemberTuple is the ONLY way org can revoke a position-holder or
// member-mapped-user tuple from its own transaction; every other tuple shape is out of reach
// through this seam by construction (the function itself rejects any other shape).
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const revokePositionOrMemberTupleSQL = `
SELECT authz.revoke_position_or_member_tuple($1, $2, $3, $4, $5, $6, $7, $8)`

// RevokePositionOrMemberTuple deletes ONE tuple of the org-owned shapes (`position:*#holder`,
// `member:*#mapped_user`, `group:*#member`, `company:*#member` — migrations/authz/0006–0008) via the SECURITY DEFINER function
// — never a raw DELETE. tx is the CALLER's own transaction (same shape as Grant/Revoke), so the
// revoke commits or rolls back atomically with whatever business write (assignment end, member
// unlink) triggered it. Deleting a tuple that doesn't exist is a no-op (idempotent), still
// ledgered — matching Revoke's own semantics. A tuple shape outside the function's allow-list
// returns an error (fail closed): this is not a general-purpose revoke.
func RevokePositionOrMemberTuple(ctx context.Context, tx pgx.Tx, actor, correlationID string, t Tuple) error {
	if t.ObjectType == "" || t.ObjectID == "" || t.Relation == "" || t.SubjectType == "" || t.SubjectID == "" {
		return fmt.Errorf("authz/store: revoke position/member tuple: tuple has an empty required field: %+v", t)
	}
	if _, err := tx.Exec(ctx, revokePositionOrMemberTupleSQL,
		actor, correlationID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation,
	); err != nil {
		return fmt.Errorf("authz/store: revoke position/member tuple: %w", err)
	}
	return nil
}
