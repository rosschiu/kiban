// SPDX-License-Identifier: Apache-2.0

package decision

import (
	"context"
	"time"
)

// Decider evaluates effective-access requests against the ordered 8-step decision using the
// injected Deps.
type Decider struct {
	deps Deps
}

// NewDecider builds a Decider. Deps' fields the caller's request shapes will actually reach
// must be non-nil (internal/authz wires all of them; test fakes wire only what each case exercises).
func NewDecider(deps Deps) *Decider {
	return &Decider{deps: deps}
}

// Evaluate runs the ordered, fail-closed effective-access decision
// for one request. Every branch appends evidence before returning, allow or deny alike
// (EA-D6/D7).
func (d *Decider) Evaluate(ctx context.Context, req Request) Decision {
	var ev []Evidence
	ev = append(ev, Evidence{Key: "featureKey", Value: req.FeatureKey}, Evidence{Key: "subjectId", Value: req.SubjectID})

	// Step 1 — subject lookup.
	subj, err := d.deps.Subject.Lookup(ctx, req.SubjectID)
	if err != nil {
		return unavailable("identity", "subject_lookup", &ev)
	}
	if !subj.Found {
		return deny(ReasonAuthUserNotFound, &ev, "subjectFound", "false")
	}

	// Step 2 — Keycloak enabled (live, never cached, never defaulted to enabled).
	kc, err := d.deps.Keycloak.Enabled(ctx, req.SubjectID)
	if err != nil {
		return unavailable("keycloak", "keycloak_enabled", &ev)
	}
	switch kc {
	case KCUnknown:
		return unavailable("keycloak", "keycloak_enabled", &ev)
	case KCFalse:
		return deny(ReasonKeycloakDisabled, &ev, "kcEnabled", "false")
	}
	ev = append(ev, Evidence{Key: "kcEnabled", Value: "true"})

	// Step 3 — lifecycle active.
	if !subj.LifecycleActive {
		return deny(ReasonUserLifecycleDisabled, &ev, "lifecycleActive", "false")
	}
	ev = append(ev, Evidence{Key: "lifecycleActive", Value: "true"})

	operatorException := false

	switch req.Scope {
	case ScopeGlobal:
		// Step 4 — global scope: platform-role match is the WHOLE decision.
		ok, err := d.deps.PlatformRole.HasRole(ctx, req.SubjectID, req.RequiredPlatformRole)
		if err != nil {
			return unavailable("engine", "platform_role", &ev)
		}
		if !ok {
			return deny(ReasonPlatformRoleRequired, &ev, "requiredPlatformRole", req.RequiredPlatformRole)
		}
		return allow(&ev, "scope", "global", "platformRole", req.RequiredPlatformRole)

	case ScopeCompany:
		// Step 5 — company scope.
		cs, err := d.deps.Company.State(ctx, req.CompanyID)
		if err != nil {
			return unavailable("org", "company_state", &ev)
		}
		if !cs.Exists || !cs.Active {
			return deny(ReasonCompanyInactive, &ev, "companyActive", "false")
		}
		ev = append(ev, Evidence{Key: "companyActive", Value: "true"})

		if req.AllowPlatformOperatorCompanyScope {
			opOK, err := d.deps.PlatformRole.HasRole(ctx, req.SubjectID, req.RequiredPlatformRole)
			if err != nil {
				return unavailable("engine", "platform_operator_exception", &ev)
			}
			if opOK {
				operatorException = true
				ev = append(ev, Evidence{Key: "platformOperatorException", Value: "true"})
			}
		}

		if !operatorException {
			ms, err := d.deps.Membership.Membership(ctx, req.CompanyID, req.SubjectID)
			if err != nil {
				return unavailable("org", "company_membership", &ev)
			}
			if !ms.IsMember {
				return deny(ReasonCompanyMembershipRequired, &ev, "isMember", "false")
			}
			if ms.Blocked {
				return deny(ReasonCompanyAccessBlocked, &ev, "accessBlocked", "true")
			}
			ev = append(ev, Evidence{Key: "isMember", Value: "true"})
		}

		if req.RequiredCompanyRole != "" && !operatorException {
			ok, err := d.deps.CompanyRole.HasRole(ctx, req.CompanyID, req.SubjectID, req.RequiredCompanyRole)
			if err != nil {
				return unavailable("org", "company_role", &ev)
			}
			if !ok {
				return deny(ReasonCompanyRoleRequired, &ev, "requiredCompanyRole", req.RequiredCompanyRole)
			}
			ev = append(ev, Evidence{Key: "companyRole", Value: req.RequiredCompanyRole})
		}
	}

	// Step 6 — module state.
	moduleEnabled, err := d.deps.ModuleState.Enabled(ctx, req.ModuleKey)
	if err != nil {
		return unavailable("registry", "module_state", &ev)
	}
	if !moduleEnabled {
		return deny(ReasonModuleDisabled, &ev, "moduleEnabled", "false")
	}
	ev = append(ev, Evidence{Key: "moduleEnabled", Value: "true"})

	// Step 7 — engine relation check (skipped when the feature has no object-relation leg).
	if req.Relation != "" {
		if dec, stop := d.relationCheck(ctx, req, req.Object, req.Relation, &ev); stop {
			return dec
		}
	}

	// Step 8 — optional business eligibility (EA-D11): 2s timeout ⇒ uncertainty, never allow;
	// non-cacheable; DENIAL vs ERROR are distinguished by the callback itself.
	if req.RequiresEligibility {
		if dec, stop := d.eligibility(ctx, req, &ev); stop {
			return dec
		}
	}

	return allow(&ev, "scope", "company")
}

// relationCheck runs step 7 for one (object, relation) pair — shared by Evaluate and the
// batch path so both bind identically. At company scope the object is first bound to the
// request's company, model-driven: a `company` object must be the
// request's company; a `company_module` object must be `<companyId>/<moduleKey>`; a type whose
// effective model defines `company` (base org types: position, group) must carry
// `<type>:<id>#company @ company:<companyId>`; a type defining `company_module` (every module
// object) must carry the `company_module` anchor pointing at `<companyId>/<moduleKey>`; a type
// defining neither cannot be bound and is denied. A missed binding is ENGINE_DENIED with
// `objectCompany=false` — never a new reason. Global scope has no object leg to bind.
func (d *Decider) relationCheck(ctx context.Context, req Request, obj ObjectRef, relation string, ev *[]Evidence) (Decision, bool) {
	objectLabel := obj.Type + ":" + obj.ID
	if req.Scope == ScopeCompany {
		moduleObjectID := req.CompanyID + "/" + req.ModuleKey
		var bound bool
		switch {
		case obj.Type == "company":
			bound = obj.ID == req.CompanyID
		case obj.Type == "company_module":
			bound = obj.ID == moduleObjectID
		case d.deps.Model != nil && d.deps.Model.Defines(obj.Type, "company"):
			anchored, err := d.deps.Engine.Check(ctx, obj.Type, obj.ID, "company", "company", req.CompanyID)
			if err != nil {
				return unavailable("engine", "relation_check", ev), true
			}
			bound = anchored
		case d.deps.Model != nil && d.deps.Model.Defines(obj.Type, "company_module"):
			anchored, err := d.deps.Engine.Check(ctx, obj.Type, obj.ID, "company_module", "company_module", moduleObjectID)
			if err != nil {
				return unavailable("engine", "relation_check", ev), true
			}
			bound = anchored
		default:
			bound = false // no company anchor in the model: unbindable, fail closed
		}
		if !bound {
			return deny(ReasonEngineDenied, ev, "objectCompany", "false", "object", objectLabel), true
		}
		*ev = append(*ev, Evidence{Key: "objectCompany", Value: "true"})
	}

	allowed, err := d.deps.Engine.Check(ctx, obj.Type, obj.ID, relation, "user", req.SubjectID)
	if err != nil {
		return unavailable("engine", "relation_check", ev), true
	}
	if !allowed {
		return deny(ReasonEngineDenied, ev, "relation", relation, "object", objectLabel), true
	}
	*ev = append(*ev, Evidence{Key: "relation", Value: relation})
	return Decision{}, false
}

// eligibility runs step 8. A Decider built without an eligibility source answers
// unavailable (never allow) so a request that sets requiresEligibility can not reach a nil
// callback.
func (d *Decider) eligibility(ctx context.Context, req Request, ev *[]Evidence) (Decision, bool) {
	if d.deps.Eligibility == nil {
		return unavailable("module-eligibility", "business_eligibility", ev), true
	}
	timeout := d.deps.EligibilityTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	eligCtx, cancel := context.WithTimeout(ctx, timeout)
	outcome, err := d.deps.Eligibility.CheckEligibility(eligCtx, req)
	timedOut := eligCtx.Err() != nil && ctx.Err() == nil
	cancel()
	if err != nil || timedOut {
		return unavailable("module-eligibility", "business_eligibility", ev), true
	}
	switch outcome {
	case EligibilityDenial:
		return deny(ReasonBusinessEligibilityDenied, ev, "eligible", "false"), true
	case EligibilityError:
		return unavailable("module-eligibility", "business_eligibility", ev), true
	}
	*ev = append(*ev, Evidence{Key: "eligible", Value: "true"})
	return Decision{}, false
}

// BatchItem is one (object,relation) pair evaluated against the SAME request context — the
// realistic batchCan shape: one subject, many objects.
type BatchItem struct {
	Object   ObjectRef
	Relation string
}

// BatchResult pairs one BatchItem with its own Decision — "each item in the batch gets its own
// reason and evidence" (the effective-access decision).
type BatchResult struct {
	Item     BatchItem
	Decision Decision
}

// EvaluateBatch runs steps 1–6 ONCE against base (they don't vary per item within one batch —
// same subject, same module, same company), then step 7 (+ step 8 if requested) per item
// against that shared, already-accumulated evidence. If the shared prefix already denies or is
// uncertain, every item gets that SAME reason (e.g. a disabled module denies every item in the
// batch with MODULE_DISABLED) — batchCan is "a batching convenience over canAccessFeature, not
// a different decision policy," but each item still gets its own reason and evidence once the
// prefix has passed.
func (d *Decider) EvaluateBatch(ctx context.Context, base Request, items []BatchItem) []BatchResult {
	prefix := base
	prefix.Relation = ""
	prefix.RequiresEligibility = false
	prefixDecision := d.Evaluate(ctx, prefix)

	results := make([]BatchResult, len(items))
	if prefixDecision.Reason != ReasonAllowed {
		for i, it := range items {
			results[i] = BatchResult{Item: it, Decision: prefixDecision}
		}
		return results
	}

	for i, it := range items {
		ev := append([]Evidence(nil), prefixDecision.Evidence...)
		results[i] = BatchResult{Item: it, Decision: d.evaluateSteps7And8(ctx, base, it, ev)}
	}
	return results
}

// evaluateSteps7And8 runs the engine check and (optionally) the business-eligibility callback
// for one batch item, given the evidence already accumulated by the shared steps 1–6 prefix.
func (d *Decider) evaluateSteps7And8(ctx context.Context, base Request, it BatchItem, ev []Evidence) Decision {
	if it.Relation != "" {
		if dec, stop := d.relationCheck(ctx, base, it.Object, it.Relation, &ev); stop {
			return dec
		}
	}

	if base.RequiresEligibility {
		itemReq := base
		itemReq.Object = it.Object
		itemReq.Relation = it.Relation
		if dec, stop := d.eligibility(ctx, itemReq, &ev); stop {
			return dec
		}
	}

	return allow(&ev)
}
