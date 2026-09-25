// SPDX-License-Identifier: Apache-2.0

// Platform-role grant/revoke: the tuple `system:platform#superadmin @ user:<subjectId>` is the
// platform role's ONLY record, so authz owns its mutation. Both routes are superadmin-gated by
// the same global-scope decision every AdminAuthorizer in the platform asks (the gateway's
// RequireSuperadmin guard asks it too, before proxying here), write the tuple through the grant
// ledger and the audit row in ONE transaction, and hold an advisory lock so two concurrent
// revokes can never leave the platform with zero superadmins.
package authz

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

type platformRoleRequestWire struct {
	SubjectID string `json:"subjectId"`
	Role      string `json:"role"`
}

// platformRoleLockSQL serializes every grant/revoke of the platform role within one
// transaction-scoped advisory lock, so the last-superadmin count below is read under the same
// lock the competing revoke would have to take. Known ceiling: one global lock; the platform
// role changes hands rarely, so throughput is irrelevant.
const platformRoleLockSQL = `SELECT pg_advisory_xact_lock(hashtext('authz.platform_role'))`

// authorizePlatformRoleChange is the superadmin gate: the bearer must pass the global-scope
// decision for featureKey with the superadmin role (the identical question internal/authz/
// client.AdminAuthorizer asks over HTTP — asked in-process here since this IS authz). Denied ⇒
// 403 (audited like every /can denial); uncertain ⇒ 503. Returns ok=false after writing.
func (svc *Service) authorizePlatformRoleChange(w http.ResponseWriter, r *http.Request, sub, featureKey string) bool {
	decider, err := svc.buildDecider(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	d := svc.evaluate(r.Context(), decider, decision.Request{
		SubjectID: sub, FeatureKey: featureKey, Scope: decision.ScopeGlobal,
		RequiredPlatformRole: store.PlatformRoleSuperadmin,
	})
	if d.Allowed {
		return true
	}
	svc.auditDenial(r.Context(), sub, featureKey, d)
	if d.Reason == decision.ReasonDependencyUnavailable {
		writeDecision(w, d)
		return false
	}
	errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "platform role changes require superadmin access: " + string(d.Reason), Details: map[string]any{"reason": string(d.Reason)}})
	return false
}

func writePlatformRoleValidation(w http.ResponseWriter, role, subjectID string) bool {
	if role != store.PlatformRoleSuperadmin {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "unknown platform role " + role, Details: map[string]any{"field": "role"}})
		return false
	}
	if subjectID == "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "subjectId is required", Details: map[string]any{"field": "subjectId"}})
		return false
	}
	return true
}

// handleGrantPlatformRole: POST /internal/authz/platform-roles {subjectId, role}. The subject
// must exist in identity (404 otherwise — a tuple for a kcSub identity has never seen would be
// inert until first login and invisible to every admin screen). Idempotent: granting an
// existing holder writes no new tuple but still ledgers and audits the call.
func (svc *Service) handleGrantPlatformRole(w http.ResponseWriter, r *http.Request) {
	sub, ok := svc.bearerSubject(w, r)
	if !ok {
		return
	}
	var req platformRoleRequestWire
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return
	}
	if !writePlatformRoleValidation(w, req.Role, req.SubjectID) {
		return
	}
	if !svc.authorizePlatformRoleChange(w, r, sub, "authz.platform_role.grant") {
		return
	}
	subject, err := svc.Identity.Lookup(r.Context(), req.SubjectID)
	if err != nil {
		writeDecision(w, decision.Decision{Reason: decision.ReasonDependencyUnavailable, Dependency: "identity", Step: "subject_lookup"})
		return
	}
	if !subject.Found {
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "subject not found in identity"})
		return
	}
	if err := svc.writePlatformRole(r.Context(), sub, req.SubjectID, "grant"); err != nil {
		writeInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"subjectId": req.SubjectID, "role": req.Role})
}

// errLastSuperadmin is the 409: the tuple being revoked is the platform's last superadmin.
type errLastSuperadmin struct{}

func (errLastSuperadmin) Error() string { return "at least one superadmin must remain" }

// handleRevokePlatformRole: DELETE /internal/authz/platform-roles/{role}/{subjectId}. 404 when
// the subject does not hold the role; 409 CONFLICT when it is the last holder — the bearer
// revoking themselves included.
func (svc *Service) handleRevokePlatformRole(w http.ResponseWriter, r *http.Request) {
	sub, ok := svc.bearerSubject(w, r)
	if !ok {
		return
	}
	role, subjectID := r.PathValue("role"), r.PathValue("subjectId")
	if !writePlatformRoleValidation(w, role, subjectID) {
		return
	}
	if !svc.authorizePlatformRoleChange(w, r, sub, "authz.platform_role.revoke") {
		return
	}
	err := svc.writePlatformRole(r.Context(), sub, subjectID, "revoke")
	switch err.(type) {
	case nil:
		errenv.WriteData(w, http.StatusOK, map[string]string{"subjectId": subjectID, "role": role})
	case errLastSuperadmin:
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeConflict, Message: err.Error()})
	case errNotHeld:
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "subject does not hold the role"})
	default:
		writeInternalError(w, err)
	}
}

type errNotHeld struct{}

func (errNotHeld) Error() string { return "platform role not held" }

// writePlatformRole is the one transaction: advisory lock, (revoke only) held + last-superadmin
// checks, tuple + ledger through store.Grant/Revoke, audit row, commit.
func (svc *Service) writePlatformRole(ctx context.Context, actor, subjectID, op string) error {
	tx, err := svc.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(ctx, platformRoleLockSQL); err != nil {
		return err
	}
	tp := store.SuperadminTuple(subjectID)
	if op == "revoke" {
		held, err := tupleHeld(ctx, tx, tp)
		if err != nil {
			return err
		}
		if !held {
			return errNotHeld{}
		}
		n, err := store.CountSuperadmins(ctx, tx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return errLastSuperadmin{}
		}
		err = store.Revoke(ctx, tx, actor, "", tp)
		if err != nil {
			return err
		}
	} else if err := store.Grant(ctx, tx, actor, "", tp); err != nil {
		return err
	}
	if err := svc.Audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "authz.platform_role." + op, Subject: "user:" + subjectID,
		Payload: map[string]any{"role": store.PlatformRoleSuperadmin, "grantedBy": actor},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func tupleHeld(ctx context.Context, tx pgx.Tx, tp store.Tuple) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject_type=$4 AND subject_id=$5 AND subject_relation=$6`,
		tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation).Scan(&n)
	return n > 0, err
}
