// SPDX-License-Identifier: Apache-2.0

// The default module-access tuple writer. A superadmin's resolution chain for
// `company_module:<companyID>/<moduleKey>#admin` needs a structural
// `company_module:<companyID>/<moduleKey>#system @ system:platform` tuple. EnsureDefaultGrant
// is that writer, called from three
// production sites (bootstrap's converge step, registry's Seed/SetEnabled, org's company
// creation) — never a raw INSERT from any of them, always this package's own audited Grant.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SystemPlatformID is the base authz model's one well-known `system` object id (model.json's
// `system#superadmin` relation anchor). internal/bootstrap defines the SAME literal as its own
// `SystemPlatformID` constant — duplicated here rather than imported (bootstrap already imports
// THIS package; the dependency can't run the other way).
const SystemPlatformID = "platform"

// EnsureDefaultGrant is the default-ONCE company-module admin grant writer: exactly once, EVER, per (companyID, moduleKey) pair, it grants
// `company_module:<companyID>/<moduleKey>#system @ system:platform` — the structural tuple that
// lets a superadmin's `company_module#admin` check resolve via the base model's
// `tupleToUserset(system, superadmin)` branch (internal/authz/engine/model.json) — through this
// package's own audited Grant (never a raw INSERT into authz.tuple). Every subsequent call for
// the SAME pair, from ANY caller, at ANY time, is a no-op: default-ONCE, never ensure-always. A
// human who later deletes the tuple (the exclusion the product requires) stays excluded
// forever; no converger/hook rerun resurrects it, because the bookkeeping claim
// below, not the tuple's current presence, is what gates re-granting.
//
// tx is the CALLER's own transaction (same shape as Grant/Revoke) — bootstrap's backfill,
// registry's Seed/SetEnabled, and org's company-creation path each run this inside their own
// already-open transaction, so the default_grant claim and the tuple write commit or roll back as
// one atomic unit with whatever business write triggered it.
//
// Idempotent under concurrency: the FIRST write is claiming the (companyID, moduleKey) row in
// authz.default_grant via `INSERT ... ON CONFLICT (company_id, module_key) DO NOTHING RETURNING`.
// Whichever concurrent transaction actually inserts the row is the one that proceeds to grant the
// tuple; every other concurrent (or later) caller sees zero rows returned and returns (false,
// nil) without touching authz.tuple at all — the same natural-key-wins pattern
// authz.tuple/authz.grant_ledger themselves already use (ON CONFLICT DO NOTHING on the tuple
// insert). Returns (true, nil) only when THIS call actually wrote the tuple.
func EnsureDefaultGrant(ctx context.Context, tx pgx.Tx, actor, correlationID, companyID, moduleKey string) (bool, error) {
	if companyID == "" || moduleKey == "" {
		return false, fmt.Errorf("authz/store: ensure default grant: companyID and moduleKey are required")
	}
	if err := EnsureCompanyModuleAnchor(ctx, tx, actor, correlationID, companyID, moduleKey); err != nil {
		return false, err
	}

	var claimed string
	err := tx.QueryRow(ctx, `
		INSERT INTO authz.default_grant (company_id, module_key, actor)
		VALUES ($1, $2, $3)
		ON CONFLICT (company_id, module_key) DO NOTHING
		RETURNING company_id
	`, companyID, moduleKey, actor).Scan(&claimed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Already defaulted before — whether the tuple is still present or was deliberately
			// removed since, default-ONCE means we stop here and never re-grant it.
			return false, nil
		}
		return false, fmt.Errorf("authz/store: claim default_grant %s/%s: %w", companyID, moduleKey, err)
	}

	objectID := companyID + "/" + moduleKey
	if err := Grant(ctx, tx, actor, correlationID, Tuple{
		ObjectType: "company_module", ObjectID: objectID, Relation: "system",
		SubjectType: "system", SubjectID: SystemPlatformID,
	}); err != nil {
		return false, fmt.Errorf("authz/store: default grant %s: %w", objectID, err)
	}
	return true, nil
}

// EnsureCompanyModuleAnchor writes the structural
// `company_module:<companyID>/<moduleKey>#company @ company:<companyID>` tuple — the anchor the
// base model's `member from company` / `admin from company` branches resolve through.
// Unlike the default grant it is ensure-ALWAYS, not default-once: it is a fact
// about which company a module instance belongs to, never a grant a human may exclude. A
// pre-check under tx keeps the audited Grant (and its ledger row) to the first write only, so
// every rerun (boot backfill, re-enable) is a silent no-op.
func EnsureCompanyModuleAnchor(ctx context.Context, tx pgx.Tx, actor, correlationID, companyID, moduleKey string) error {
	objectID := companyID + "/" + moduleKey
	var existed int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuple
		WHERE object_type='company_module' AND object_id=$1 AND relation='company'
		  AND subject_type='company' AND subject_id=$2 AND subject_relation=''`,
		objectID, companyID,
	).Scan(&existed); err != nil {
		return fmt.Errorf("authz/store: company_module anchor precheck %s: %w", objectID, err)
	}
	if existed > 0 {
		return nil
	}
	if err := Grant(ctx, tx, actor, correlationID, Tuple{
		ObjectType: "company_module", ObjectID: objectID, Relation: "company",
		SubjectType: "company", SubjectID: companyID,
	}); err != nil {
		return fmt.Errorf("authz/store: company_module anchor %s: %w", objectID, err)
	}
	return nil
}
