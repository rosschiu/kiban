// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// This file backfills evaluate.go branches decision_test.go's 13-reason suite didn't reach:
// every dependency's own transport-error path (not just Subject's, at step 1), the step-8
// eligibility timeout path (distinct from the EligibilityError outcome), EvaluateBatch's
// prefix-denied fan-out, and evaluateSteps7And8's own engine-error/eligibility branches per item.

func TestDecisionDependencyErrorsAtEveryStep(t *testing.T) {
	cases := []struct {
		name     string
		req      func() decision.Request
		mutate   func(decision.Deps) decision.Deps
		wantDep  string
		wantStep string
	}{
		{
			name: "keycloak enabled transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.Keycloak = fakeKeycloak{err: errors.New("boom")}
				return d
			},
			wantDep: "keycloak", wantStep: "keycloak_enabled",
		},
		{
			name: "global scope platform-role transport error",
			req:  globalRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.PlatformRole = fakePlatformRole{err: errors.New("boom")}
				return d
			},
			wantDep: "engine", wantStep: "platform_role",
		},
		{
			name: "company state transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.Company = fakeCompany{err: errors.New("boom")}
				return d
			},
			wantDep: "org", wantStep: "company_state",
		},
		{
			name: "platform-operator exception transport error",
			req: func() decision.Request {
				r := companyRequest()
				r.AllowPlatformOperatorCompanyScope = true
				return r
			},
			mutate: func(d decision.Deps) decision.Deps {
				d.PlatformRole = fakePlatformRole{err: errors.New("boom")}
				return d
			},
			wantDep: "engine", wantStep: "platform_operator_exception",
		},
		{
			name: "membership transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.Membership = fakeMembership{err: errors.New("boom")}
				return d
			},
			wantDep: "org", wantStep: "company_membership",
		},
		{
			name: "company role transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.CompanyRole = fakeCompanyRole{err: errors.New("boom")}
				return d
			},
			wantDep: "org", wantStep: "company_role",
		},
		{
			name: "module state transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.ModuleState = fakeModuleState{err: errors.New("boom")}
				return d
			},
			wantDep: "registry", wantStep: "module_state",
		},
		{
			name: "engine relation-check transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.Engine = fakeEngine{err: errors.New("boom")}
				return d
			},
			wantDep: "engine", wantStep: "relation_check",
		},
		{
			name: "eligibility callback transport error",
			req:  companyRequest,
			mutate: func(d decision.Deps) decision.Deps {
				d.Eligibility = fakeEligibility{err: errors.New("boom")}
				return d
			},
			wantDep: "module-eligibility", wantStep: "business_eligibility",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.mutate(happyDeps())
			got := decision.NewDecider(deps).Evaluate(context.Background(), tc.req())
			if got.Allowed {
				t.Fatalf("a dependency error must never allow, got %+v", got)
			}
			if got.Reason != decision.ReasonDependencyUnavailable {
				t.Fatalf("reason = %s, want DEPENDENCY_UNAVAILABLE (evidence=%+v)", got.Reason, got.Evidence)
			}
			if got.Dependency != tc.wantDep || got.Step != tc.wantStep {
				t.Fatalf("EA-D6 telemetry: dependency=%q step=%q, want dependency=%q step=%q", got.Dependency, got.Step, tc.wantDep, tc.wantStep)
			}
		})
	}
}

// slowEligibility blocks past its context's deadline before returning, to exercise the timedOut
// branch (distinct from returning EligibilityError outright).
type slowEligibility struct {
	sleep   time.Duration
	outcome decision.EligibilityOutcome
}

func (s slowEligibility) CheckEligibility(ctx context.Context, req decision.Request) (decision.EligibilityOutcome, error) {
	select {
	case <-time.After(s.sleep):
		return s.outcome, nil
	case <-ctx.Done():
		return s.outcome, nil
	}
}

func TestDecisionEligibilityTimeout(t *testing.T) {
	deps := happyDeps()
	deps.EligibilityTimeout = 5 * time.Millisecond
	deps.Eligibility = slowEligibility{sleep: 50 * time.Millisecond, outcome: decision.EligibilityAllow}

	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	if got.Allowed {
		t.Fatalf("a timed-out eligibility callback must never allow, got %+v", got)
	}
	if got.Reason != decision.ReasonDependencyUnavailable {
		t.Fatalf("reason = %s, want DEPENDENCY_UNAVAILABLE", got.Reason)
	}
	if got.Dependency != "module-eligibility" || got.Step != "business_eligibility" {
		t.Fatalf("EA-D6 telemetry wrong: dependency=%q step=%q", got.Dependency, got.Step)
	}
}

// TestDecisionEligibilityDefaultTimeoutIsUsedWhenUnset proves the EA-D11 2s default is applied
// when Deps.EligibilityTimeout is zero (the `if timeout <= 0` branch), using an eligibility fake
// that resolves well within 2s so the test itself stays fast.
func TestDecisionEligibilityDefaultTimeoutIsUsedWhenUnset(t *testing.T) {
	deps := happyDeps()
	deps.EligibilityTimeout = 0
	deps.Eligibility = fakeEligibility{outcome: decision.EligibilityAllow}

	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	if !got.Allowed {
		t.Fatalf("want allow with the default 2s eligibility timeout, got %+v", got)
	}
}

// TestDecisionBatchPrefixDeniedFansOutSameReason covers EvaluateBatch's early-return branch:
// when the shared steps-1-6 prefix doesn't reach ALLOWED, every item gets that identical
// decision, and neither step 7 (engine) nor step 8 (eligibility) is evaluated per item.
func TestDecisionBatchPrefixDeniedFansOutSameReason(t *testing.T) {
	deps := happyDeps()
	deps.ModuleState = fakeModuleState{enabled: false}
	deps.Engine = fakeEngine{err: errors.New("must not be called — prefix already denied")}

	base := companyRequest()
	items := []decision.BatchItem{
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/m1"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/m2"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/m3"}, Relation: "viewer"},
	}
	results := decision.NewDecider(deps).EvaluateBatch(context.Background(), base, items)
	if len(results) != len(items) {
		t.Fatalf("got %d results, want %d", len(results), len(items))
	}
	for i, r := range results {
		if r.Decision.Allowed {
			t.Fatalf("item %d: want deny (module disabled), got allow", i)
		}
		if r.Decision.Reason != decision.ReasonModuleDisabled {
			t.Fatalf("item %d: reason = %s, want MODULE_DISABLED", i, r.Decision.Reason)
		}
		if r.Item != items[i] {
			t.Fatalf("item %d: BatchResult.Item = %+v, want %+v", i, r.Item, items[i])
		}
	}
}

// TestDecisionBatchItemEngineError proves a per-item engine transport error in
// evaluateSteps7And8 resolves that ONE item to DEPENDENCY_UNAVAILABLE without affecting a
// sibling item evaluated against a working engine.
func TestDecisionBatchItemEngineError(t *testing.T) {
	deps := happyDeps()
	deps.Engine = &erroringOnObjectEngine{failObjectID: "broken"}
	deps.Model = bindingModel

	base := companyRequest()
	base.RequiresEligibility = false
	// Module-typed objects: the engine answers the company-anchor check and the relation check
	// alike (true, or an error for the broken object).
	items := []decision.BatchItem{
		{Object: decision.ObjectRef{Type: "doc", ID: "broken"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "doc", ID: "ok"}, Relation: "viewer"},
	}
	results := decision.NewDecider(deps).EvaluateBatch(context.Background(), base, items)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Decision.Allowed || results[0].Decision.Reason != decision.ReasonDependencyUnavailable {
		t.Fatalf("item 0: want DEPENDENCY_UNAVAILABLE, got %+v", results[0].Decision)
	}
	if results[0].Decision.Dependency != "engine" || results[0].Decision.Step != "relation_check" {
		t.Fatalf("item 0 telemetry: dependency=%q step=%q", results[0].Decision.Dependency, results[0].Decision.Step)
	}
	if !results[1].Decision.Allowed {
		t.Fatalf("item 1: a sibling item's engine error must not affect this item's own result, got %+v", results[1].Decision)
	}
}

type erroringOnObjectEngine struct {
	failObjectID string
}

func (e *erroringOnObjectEngine) Check(ctx context.Context, objType, objID, relation, subjType, subjID string) (bool, error) {
	if objID == e.failObjectID {
		return false, errors.New("engine unreachable")
	}
	return true, nil
}

// TestDecisionBatchItemEligibility proves evaluateSteps7And8 runs step 8 per item (denial,
// error, and allow outcomes), sharing the already-passed steps 1-6 evidence.
func TestDecisionBatchItemEligibility(t *testing.T) {
	deps := happyDeps()
	deps.Engine = fakeEngine{allowed: true}
	deps.Model = bindingModel
	deps.Eligibility = &perObjectEligibility{
		outcomes: map[string]decision.EligibilityOutcome{
			"deny":  decision.EligibilityDenial,
			"error": decision.EligibilityError,
			"allow": decision.EligibilityAllow,
		},
	}

	base := companyRequest()
	base.RequiresEligibility = true
	// Module-typed objects whose company anchor the (always-true) fake engine confirms.
	items := []decision.BatchItem{
		{Object: decision.ObjectRef{Type: "doc", ID: "deny"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "doc", ID: "error"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "doc", ID: "allow"}, Relation: "viewer"},
	}
	results := decision.NewDecider(deps).EvaluateBatch(context.Background(), base, items)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Decision.Allowed || results[0].Decision.Reason != decision.ReasonBusinessEligibilityDenied {
		t.Fatalf("item 0 (deny): got %+v", results[0].Decision)
	}
	if results[1].Decision.Allowed || results[1].Decision.Reason != decision.ReasonDependencyUnavailable {
		t.Fatalf("item 1 (error): got %+v", results[1].Decision)
	}
	if !results[2].Decision.Allowed || results[2].Decision.Reason != decision.ReasonAllowed {
		t.Fatalf("item 2 (allow): got %+v", results[2].Decision)
	}
}

type perObjectEligibility struct {
	outcomes map[string]decision.EligibilityOutcome
}

func (p *perObjectEligibility) CheckEligibility(ctx context.Context, req decision.Request) (decision.EligibilityOutcome, error) {
	return p.outcomes[req.Object.ID], nil
}

// TestDecisionRelationSkippedWhenEmpty proves step 7 is treated as satisfied (never calls the
// engine) when Relation == "" — some features are pure role/eligibility gates.
func TestDecisionRelationSkippedWhenEmpty(t *testing.T) {
	deps := happyDeps()
	deps.Engine = fakeEngine{err: errors.New("must not be called when Relation is empty")}
	req := companyRequest()
	req.Relation = ""
	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if !got.Allowed {
		t.Fatalf("want allow (relation leg skipped), got %+v", got)
	}
}
