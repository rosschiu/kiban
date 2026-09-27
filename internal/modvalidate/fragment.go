// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// validateFragment runs every authz.fragment.json contract rule that needs only the fragment
// itself plus the owning manifest's moduleKey (no cross-module state).
func validateFragment(moduleKey string, f *AuthzFragment) []ValidationError {
	var errs []ValidationError
	mk := moduleKey

	if f.ModuleKey != moduleKey {
		errs = append(errs, errf(mk, RuleFragmentModuleKeyMismatch,
			"authz.fragment.json: moduleKey %q does not match module.manifest.json's moduleKey %q", f.ModuleKey, moduleKey))
	}

	prefix := moduleKey + "."
	for _, feat := range f.Features {
		if !strings.HasPrefix(feat.FeatureKey, prefix) {
			errs = append(errs, errf(mk, RuleFeaturePrefixMismatch,
				"authz.fragment.json: feature key %q must start with %q (module.scope.action)", feat.FeatureKey, prefix))
		}
	}

	// Subset wall: reuse internal/authz/engine's own model loader
	// — it is the platform's ONE implementation of "this / computedUserset / tupleToUserset /
	// union only", never reimplemented here. engine.LoadModel takes exactly the `relations`
	// sub-document's shape (object type -> relation -> expression).
	// effective is the model a check against this module actually runs on: the base model plus
	// the fragment's own relations (the same merge internal/authz/fragment.Load performs).
	effective := engine.BaseModel
	if len(f.Relations) > 0 {
		m, err := engine.LoadModel(f.Relations)
		if err != nil {
			errs = append(errs, errf(mk, RuleAuthzSubsetWall, "authz.fragment.json: relations: %v", err))
		} else {
			// A fragment MAY REFERENCE the platform base model's relations (e.g.
			// `company_module` as a tupleset target) but may never DECLARE/REDEFINE a base
			// object type as one of its own top-level `relations` keys — the base model is
			// always loaded (internal/authz/engine.BaseModel) and fragment.Load asserts the
			// same rule again at merge time; this is the install-time half of that one rule.
			// (Merge refuses the collision too; the base types are dropped from the fragment
			// first so the remaining rules still run over the rest of it.)
			for typ := range m {
				if engine.IsBaseType(typ) {
					errs = append(errs, errf(mk, RuleAuthzBaseTypeRedeclared,
						"authz.fragment.json: relations: object type %q is a platform base type — "+
							"fragments may reference base relations but never declare/redefine a base type", typ))
					delete(m, typ)
				}
			}
			if effective, err = effective.Merge(m); err != nil {
				errs = append(errs, errf(mk, RuleAuthzBaseTypeRedeclared, "authz.fragment.json: relations: %v", err))
				effective = engine.BaseModel
			}
			// Cross-type tupleToUserset targets: LoadModel checks only
			// same-type references; the computedUserset half must exist somewhere in the
			// effective model or every eval reaching it is an UNKNOWN_RELATION 503.
			if err := effective.ValidateTupleToUsersetTargets(); err != nil {
				errs = append(errs, errf(mk, RuleAuthzRelationUnknown, "authz.fragment.json: relations: %v", err))
			}
			// Every declared type carries the company anchor the decision layer binds object
			// checks through; fragment.Load asserts the same at merge.
			if err := m.ValidateCompanyModuleAnchor(); err != nil {
				errs = append(errs, errf(mk, RuleAuthzAnchorMissing, "authz.fragment.json: relations: %v", err))
			}
		}
	}

	// An access rule's (objectType, relation) must exist in the effective model — otherwise the
	// feature can never match (timesheet/notification once anchored on a `company_module#member`
	// the base model did not define).
	for _, feat := range f.Features {
		if !allowedScopeTypes[feat.ScopeType] {
			errs = append(errs, errf(mk, RuleFragmentFeatureInvalid,
				"authz.fragment.json: feature %q: scopeType %q must be \"global\" or \"company\"", feat.FeatureKey, feat.ScopeType))
		}
		if !allowedAccessRuleKinds[feat.AccessRuleKind] {
			errs = append(errs, errf(mk, RuleFragmentFeatureInvalid,
				"authz.fragment.json: feature %q: accessRuleKind %q must be one of %v", feat.FeatureKey, feat.AccessRuleKind, slices.Sorted(maps.Keys(allowedAccessRuleKinds))))
		}
		objType, _ := feat.AccessRulePayload["objectType"].(string)
		rel, _ := feat.AccessRulePayload["relation"].(string)
		if objType == "" && rel == "" {
			continue
		}
		if _, ok := effective[objType][rel]; !ok {
			errs = append(errs, errf(mk, RuleAuthzRelationUnknown,
				"authz.fragment.json: feature %q: accessRulePayload relation %q is not defined on object type %q in the effective model (base model + this fragment's relations)",
				feat.FeatureKey, rel, objType))
		}
	}

	// objects[]/roles[]/rowScopes[] are cross-checked against the
	// effective model instead of being decoded and ignored.
	for _, role := range f.Roles {
		if !allowedScopeTypes[role.ScopeType] {
			errs = append(errs, errf(mk, RuleFragmentRoleInvalid,
				"authz.fragment.json: role %q: scopeType %q must be \"global\" or \"company\"", role.RoleKey, role.ScopeType))
		}
	}
	declared := map[string]bool{}
	for _, o := range f.Objects {
		declared[o.ObjectType] = true
		rels, known := effective[o.ObjectType]
		if !known || engine.IsBaseType(o.ObjectType) {
			errs = append(errs, errf(mk, RuleFragmentObjectInvalid,
				"authz.fragment.json: object %q is not declared in this fragment's relations", o.ObjectType))
			continue
		}
		if !allowedScopeKinds[o.ScopeKind] {
			errs = append(errs, errf(mk, RuleFragmentObjectInvalid,
				"authz.fragment.json: object %q: scopeKind %q must be one of %v", o.ObjectType, o.ScopeKind, slices.Sorted(maps.Keys(allowedScopeKinds))))
		}
		if _, ok := effective[o.ParentKind]; !ok {
			errs = append(errs, errf(mk, RuleFragmentObjectInvalid,
				"authz.fragment.json: object %q: parentKind %q is not an object type of the effective model", o.ObjectType, o.ParentKind))
		}
		if _, ok := rels[o.ManagerRelation]; !ok {
			errs = append(errs, errf(mk, RuleFragmentObjectInvalid,
				"authz.fragment.json: object %q: managerRelation %q is not a relation of that object type", o.ObjectType, o.ManagerRelation))
		}
		for _, gr := range o.GrantableRelations {
			if _, ok := rels[gr]; !ok {
				errs = append(errs, errf(mk, RuleFragmentObjectInvalid,
					"authz.fragment.json: object %q: grantableRelations entry %q is not a relation of that object type", o.ObjectType, gr))
			}
		}
	}
	for _, rs := range f.RowScopes {
		if _, ok := effective[rs.EntityType]; !ok || engine.IsBaseType(rs.EntityType) {
			errs = append(errs, errf(mk, RuleFragmentRowScopeInvalid,
				"authz.fragment.json: rowScopes entityType %q is not an object type this fragment declares", rs.EntityType))
		}
	}

	return errs
}

var allowedAccessRuleKinds = map[string]bool{"relation": true, "platform_role": true, "module_eligibility": true}
var allowedScopeKinds = map[string]bool{"module": true, "directory": true, "object": true, "document": true}

// syntheticAccessFeatureKey is the platform-synthesized "<moduleKey>.access" feature key every
// registry-known+enabled module gets at company scope (internal/authz/summary.go, documented
// there as "the honest ceiling of what featureKeys can mean right now"). It is never declared in
// any module's own authz.fragment.json (nothing loads fragments into the live authz engine yet),
// so frontend routes gating on it are a documented,
// intentional exception to "frontend feature keys absent from the authz fragment".
func syntheticAccessFeatureKey(moduleKey string) string {
	return moduleKey + ".access"
}

func fragmentFeatureKeySet(f *AuthzFragment) map[string]bool {
	set := map[string]bool{}
	if f == nil {
		return set
	}
	for _, feat := range f.Features {
		set[feat.FeatureKey] = true
	}
	return set
}

// fragmentObjectTypes is every object type a fragment claims: its `objects[].objectType`
// entries and its `relations` keys (the types the engine actually loads —
// two modules declaring one type in `relations` is a catalog duplicate), deduplicated,
// sorted.
func fragmentObjectTypes(f *AuthzFragment) []string {
	if f == nil {
		return nil
	}
	set := map[string]bool{}
	for _, o := range f.Objects {
		set[o.ObjectType] = true
	}
	var rels map[string]json.RawMessage
	if len(f.Relations) > 0 && json.Unmarshal(f.Relations, &rels) == nil {
		for typ := range rels {
			set[typ] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

func fragmentFeatureKeys(f *AuthzFragment) []string {
	if f == nil {
		return nil
	}
	out := make([]string, 0, len(f.Features))
	for _, feat := range f.Features {
		out = append(out, feat.FeatureKey)
	}
	return out
}
