// SPDX-License-Identifier: Apache-2.0

// The EffectiveAccessSummary composition (the effective-access "Summary
// contract").
//
// This composes each field from data the system genuinely has today, never inventing a new
// storage surface (no new deps, no decision caching):
//   - featureKeys: re-derives "is this ALLOWED" per feature via the SAME decision.Decider every
//     enforcement call already uses (never a separate, potentially-drifting answer) — the one
//     feature key actually wired into this codebase today (auth.platform_administration.access,
//     mirrored from gateway's platform_admin.go/registry's adminauthz.go) plus one synthesized
//     "<moduleKey>.access" feature per registry-known+enabled module, evaluated at company scope
//     when a companyId is given. There is no feature/manifest catalog yet, so this is the
//     honest ceiling of what "featureKeys" can mean right now.
//   - roleBindings: the platform role (DB-backed, same PlatformRoleSource every decision uses)
//     plus, when a companyId is given, the company type's own declared non-system relations
//     (internal/authz/harness/model.fga: "admin", "viewer") checked directly against the engine —
//     there is no grantable-relations catalog yet either, so these two are the full honest set.
//   - objectAccess: every DIRECT tuple naming the subject (internal/authz/store.
//     ListDirectTuplesForSubject), grouped by object.
//   - rowScopes / fieldPolicies: empty arrays. Segment-rule compilation and field-policy
//     evaluation are not built yet.
package authz

import (
	"context"
	"net/http"
	"sort"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

// summarySuperadminFeatureKey/summarySuperadminRole mirror gateway's platform_admin.go and
// registry's adminauthz.go exactly — the one feature key genuinely wired into this codebase's
// runtime today.
const (
	summarySuperadminFeatureKey = "auth.platform_administration.access"
	summarySuperadminRole       = "kiban-superadmin"
)

// summaryCompanyRelations are the company type's own declared non-system relations
// (internal/authz/harness/model.fga: "define admin: ... / define viewer: [user] or admin") — the only company-
// scoped "role" concept this codebase's engine model defines today.
var summaryCompanyRelations = []string{"admin", "viewer"}

// handleSummary answers `GET /internal/authz/effective-access/summary?kcSub=&companyId=`.
// kcSub is required; companyId is optional — company-scoped fields (the per-module
// featureKeys and company roleBindings) are simply omitted when it's absent, never guessed.
func (svc *Service) handleSummary(w http.ResponseWriter, r *http.Request) {
	kcSub := r.URL.Query().Get("kcSub")
	if kcSub == "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code: errenv.CodeBadRequest, Message: "kcSub query param is required", Details: map[string]string{"field": "kcSub"},
		})
		return
	}
	companyID := r.URL.Query().Get("companyId")

	decider, checker, err := svc.buildDeciderAndChecker(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	objectAccess, err := summaryObjectAccess(r.Context(), svc.Pool, kcSub)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	errenv.WriteData(w, http.StatusOK, map[string]any{
		"apiVersion": 1,
		"subjectId":  kcSub,
		"companyId":  companyID,
		// This summary composes across ALL modules at once (the shell nav's data source), so
		// it is never itself module-scoped — the contract's singular "moduleKey" field is
		// always empty here.
		"moduleKey":     "",
		"featureKeys":   svc.summaryFeatureKeys(r.Context(), decider, kcSub, companyID),
		"roleBindings":  svc.summaryRoleBindings(r.Context(), checker, kcSub, companyID),
		"objectAccess":  objectAccess,
		"rowScopes":     []any{},
		"fieldPolicies": []any{},
	})
}

// summaryFeatureKeys re-derives ALLOWED-ness per feature via the real Decider — never a second,
// potentially-drifting notion of "access." A dependency error narrows the result (the feature is
// simply left out) rather than failing the whole summary or fabricating an allow — this endpoint
// is a display composition, not an enforcement decision (the real gate stays `/can`/`batch-can`).
func (svc *Service) summaryFeatureKeys(ctx context.Context, decider *decision.Decider, kcSub, companyID string) []string {
	keys := []string{}

	superadmin := decider.Evaluate(ctx, decision.Request{
		SubjectID: kcSub, FeatureKey: summarySuperadminFeatureKey,
		Scope: decision.ScopeGlobal, RequiredPlatformRole: summarySuperadminRole,
	})
	if superadmin.Reason == decision.ReasonAllowed {
		keys = append(keys, summarySuperadminFeatureKey)
	}

	if companyID == "" {
		return keys
	}
	known, err := svc.KnownEnabled(ctx)
	if err != nil {
		return keys
	}
	modules := make([]string, 0, len(known))
	for moduleKey, enabled := range known {
		if enabled {
			modules = append(modules, moduleKey)
		}
	}
	sort.Strings(modules)
	for _, moduleKey := range modules {
		d := decider.Evaluate(ctx, decision.Request{
			SubjectID: kcSub, FeatureKey: moduleKey + ".access", ModuleKey: moduleKey,
			Scope: decision.ScopeCompany, CompanyID: companyID,
		})
		if d.Reason == decision.ReasonAllowed {
			keys = append(keys, moduleKey+".access")
		}
	}
	return keys
}

// summaryRoleBindings reports the platform role (if held) plus, when companyID is given, every
// summaryCompanyRelations entry the subject holds on that company — each a direct engine check,
// same fail-soft-narrow posture as summaryFeatureKeys (an error omits the entry, never fabricates
// one).
func (svc *Service) summaryRoleBindings(ctx context.Context, checker decision.EngineChecker, kcSub, companyID string) []map[string]any {
	bindings := []map[string]any{}

	if hasRole, err := (enginePlatformRoleSource{checker: checker}).HasRole(ctx, kcSub, summarySuperadminRole); err == nil && hasRole {
		bindings = append(bindings, map[string]any{"scope": "global", "role": summarySuperadminRole})
	}

	if companyID == "" {
		return bindings
	}
	for _, role := range summaryCompanyRelations {
		if ok, err := checker.Check(ctx, "company", companyID, role, "user", kcSub); err == nil && ok {
			bindings = append(bindings, map[string]any{"scope": "company", "companyId": companyID, "role": role})
		}
	}
	return bindings
}

// summaryObjectAccess lists every direct tuple naming kcSub as the subject, grouped by
// (objectType, objectId) into the contract's `{objectType, objectId, relations[]}` shape.
func summaryObjectAccess(ctx context.Context, q store.Queryer, kcSub string) ([]map[string]any, error) {
	tuples, err := store.ListDirectTuplesForSubject(ctx, q, "user", kcSub)
	if err != nil {
		return nil, err
	}
	type objectKey struct{ objectType, objectID string }
	var order []objectKey
	relationsByObject := map[objectKey][]string{}
	for _, t := range tuples {
		k := objectKey{t.ObjectType, t.ObjectID}
		if _, seen := relationsByObject[k]; !seen {
			order = append(order, k)
		}
		relationsByObject[k] = append(relationsByObject[k], t.Relation)
	}
	out := make([]map[string]any, 0, len(order))
	for _, k := range order {
		out = append(out, map[string]any{
			"objectType": k.objectType, "objectId": k.objectID, "relations": relationsByObject[k],
		})
	}
	return out, nil
}
