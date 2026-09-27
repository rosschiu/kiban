// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// --- Fakes: every dependency is faked here (real HTTP/engine wiring is tested elsewhere). ---

type fakeSubject struct {
	result decision.SubjectResult
	err    error
}

func (f fakeSubject) Lookup(ctx context.Context, subjectID string) (decision.SubjectResult, error) {
	return f.result, f.err
}

type fakeKeycloak struct {
	state decision.KCState
	err   error
}

func (f fakeKeycloak) Enabled(ctx context.Context, subjectID string) (decision.KCState, error) {
	return f.state, f.err
}

type fakePlatformRole struct {
	has bool
	err error
}

func (f fakePlatformRole) HasRole(ctx context.Context, subjectID, role string) (bool, error) {
	return f.has, f.err
}

type fakeCompany struct {
	state decision.CompanyState
	err   error
}

func (f fakeCompany) State(ctx context.Context, companyID string) (decision.CompanyState, error) {
	return f.state, f.err
}

type fakeMembership struct {
	state decision.MembershipState
	err   error
}

func (f fakeMembership) Membership(ctx context.Context, companyID, subjectID string) (decision.MembershipState, error) {
	return f.state, f.err
}

type fakeCompanyRole struct {
	has bool
	err error
}

func (f fakeCompanyRole) HasRole(ctx context.Context, companyID, subjectID, role string) (bool, error) {
	return f.has, f.err
}

type fakeModuleState struct {
	enabled bool
	err     error
}

func (f fakeModuleState) Enabled(ctx context.Context, moduleKey string) (bool, error) {
	return f.enabled, f.err
}

type fakeEngine struct {
	allowed bool
	err     error
}

func (f fakeEngine) Check(ctx context.Context, objType, objID, relation, subjType, subjID string) (bool, error) {
	return f.allowed, f.err
}

type fakeEligibility struct {
	outcome decision.EligibilityOutcome
	err     error
}

func (f fakeEligibility) CheckEligibility(ctx context.Context, req decision.Request) (decision.EligibilityOutcome, error) {
	return f.outcome, f.err
}

// happyDeps is a full set of dependencies that, together with happyCompanyRequest, reaches
// ALLOWED — each test case overrides exactly the one dependency needed to force its target
// reason, so a passing baseline proves the override (not some other unrelated bug) caused the
// denial.
func happyDeps() decision.Deps {
	return decision.Deps{
		Subject:      fakeSubject{result: decision.SubjectResult{Found: true, LifecycleActive: true}},
		Keycloak:     fakeKeycloak{state: decision.KCTrue},
		PlatformRole: fakePlatformRole{has: true},
		Company:      fakeCompany{state: decision.CompanyState{Exists: true, Active: true}},
		Membership:   fakeMembership{state: decision.MembershipState{IsMember: true, Blocked: false}},
		CompanyRole:  fakeCompanyRole{has: true},
		ModuleState:  fakeModuleState{enabled: true},
		Engine:       fakeEngine{allowed: true},
		Eligibility:  fakeEligibility{outcome: decision.EligibilityAllow},
	}
}

func companyRequest() decision.Request {
	return decision.Request{
		SubjectID:           "user-1",
		FeatureKey:          "test.feature.access",
		ModuleKey:           "test-module",
		Scope:               decision.ScopeCompany,
		CompanyID:           "company-1",
		RequiredCompanyRole: "editor",
		Object:              decision.ObjectRef{Type: "company_module", ID: "company-1/test-module"},
		Relation:            "viewer",
		RequiresEligibility: true,
	}
}

func globalRequest() decision.Request {
	return decision.Request{
		SubjectID:            "user-1",
		FeatureKey:           "test.feature.global",
		ModuleKey:            "test-module",
		Scope:                decision.ScopeGlobal,
		RequiredPlatformRole: "kiban-superadmin",
	}
}

// coverage tracks which of the 13 reasons this test file actually exercises — asserted
// exhaustive at the end (13/13 reasons covered).
var coverage = map[decision.Reason]bool{}

func record(t *testing.T, got decision.Decision, want decision.Reason) {
	t.Helper()
	if got.Reason != want {
		t.Fatalf("reason = %s, want %s (evidence=%+v)", got.Reason, want, got.Evidence)
	}
	if len(got.Evidence) == 0 {
		t.Fatalf("decision for %s carries no evidence — every decision must (EA-D6/D7)", want)
	}
	coverage[want] = true
}

func TestDecisionAllowedCompany(t *testing.T) {
	d := decision.NewDecider(happyDeps())
	got := d.Evaluate(context.Background(), companyRequest())
	if !got.Allowed {
		t.Fatalf("want allowed, got %+v", got)
	}
	record(t, got, decision.ReasonAllowed)
}

func TestDecisionAllowedGlobal(t *testing.T) {
	d := decision.NewDecider(happyDeps())
	got := d.Evaluate(context.Background(), globalRequest())
	if !got.Allowed {
		t.Fatalf("want allowed, got %+v", got)
	}
	if got.Reason != decision.ReasonAllowed {
		t.Fatalf("reason = %s, want ALLOWED", got.Reason)
	}
}

func TestDecisionAuthUserNotFound(t *testing.T) {
	deps := happyDeps()
	deps.Subject = fakeSubject{result: decision.SubjectResult{Found: false}}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonAuthUserNotFound)
}

func TestDecisionKeycloakDisabled(t *testing.T) {
	deps := happyDeps()
	deps.Keycloak = fakeKeycloak{state: decision.KCFalse}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonKeycloakDisabled)
}

func TestDecisionUnknownKeycloakStateIsUnavailableNeverAllow(t *testing.T) {
	deps := happyDeps()
	deps.Keycloak = fakeKeycloak{state: decision.KCUnknown}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	if got.Allowed {
		t.Fatalf("unknown Keycloak state must never allow, got %+v", got)
	}
	record(t, got, decision.ReasonDependencyUnavailable)
	if got.Dependency != "keycloak" {
		t.Fatalf("dependency = %q, want keycloak", got.Dependency)
	}
}

func TestDecisionUserLifecycleDisabled(t *testing.T) {
	deps := happyDeps()
	deps.Subject = fakeSubject{result: decision.SubjectResult{Found: true, LifecycleActive: false}}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonUserLifecycleDisabled)
}

func TestDecisionCompanyInactive(t *testing.T) {
	deps := happyDeps()
	deps.Company = fakeCompany{state: decision.CompanyState{Exists: true, Active: false}}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonCompanyInactive)
}

func TestDecisionCompanyMembershipRequired(t *testing.T) {
	deps := happyDeps()
	deps.Membership = fakeMembership{state: decision.MembershipState{IsMember: false}}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonCompanyMembershipRequired)
}

func TestDecisionCompanyAccessBlocked(t *testing.T) {
	deps := happyDeps()
	deps.Membership = fakeMembership{state: decision.MembershipState{IsMember: true, Blocked: true}}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonCompanyAccessBlocked)
}

func TestDecisionCompanyRoleRequired(t *testing.T) {
	deps := happyDeps()
	deps.CompanyRole = fakeCompanyRole{has: false}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonCompanyRoleRequired)
}

func TestDecisionModuleDisabled(t *testing.T) {
	deps := happyDeps()
	deps.ModuleState = fakeModuleState{enabled: false}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonModuleDisabled)
}

func TestDecisionPlatformRoleRequired(t *testing.T) {
	deps := happyDeps()
	deps.PlatformRole = fakePlatformRole{has: false}
	got := decision.NewDecider(deps).Evaluate(context.Background(), globalRequest())
	record(t, got, decision.ReasonPlatformRoleRequired)
}

func TestDecisionEngineDenied(t *testing.T) {
	deps := happyDeps()
	deps.Engine = fakeEngine{allowed: false}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonEngineDenied)
}

func TestDecisionBusinessEligibilityDenied(t *testing.T) {
	deps := happyDeps()
	deps.Eligibility = fakeEligibility{outcome: decision.EligibilityDenial}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonBusinessEligibilityDenied)
}

func TestDecisionDependencyUnavailableFromEligibilityError(t *testing.T) {
	deps := happyDeps()
	deps.Eligibility = fakeEligibility{outcome: decision.EligibilityError}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	record(t, got, decision.ReasonDependencyUnavailable)
}

// TestDecisionDependencyUnavailableFromError proves an ordinary transport error at ANY step
// collapses to DEPENDENCY_UNAVAILABLE, never a guessed allow/deny — exercised at step 1 (the
// engine check further down the chain is never reached).
func TestDecisionDependencyUnavailableFromError(t *testing.T) {
	deps := happyDeps()
	deps.Subject = fakeSubject{err: errors.New("boom")}
	got := decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
	if got.Allowed {
		t.Fatalf("a dependency error must never allow, got %+v", got)
	}
	if got.Reason != decision.ReasonDependencyUnavailable {
		t.Fatalf("reason = %s, want DEPENDENCY_UNAVAILABLE", got.Reason)
	}
	if got.Dependency != "identity" || got.Step != "subject_lookup" {
		t.Fatalf("EA-D6 telemetry fields wrong: dependency=%q step=%q", got.Dependency, got.Step)
	}
}

func TestDecisionOperatorExceptionSkipsMembership(t *testing.T) {
	deps := happyDeps()
	deps.Membership = fakeMembership{err: errors.New("membership source unreachable — must not be called")}
	req := companyRequest()
	req.AllowPlatformOperatorCompanyScope = true
	req.RequiredPlatformRole = "kiban-superadmin"
	req.RequiredCompanyRole = ""
	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if !got.Allowed {
		t.Fatalf("platform-operator exception should allow without ever calling Membership: %+v", got)
	}
}

// TestDecisionEvidenceCompleteness proves every reason's decision carries non-empty evidence,
// across a representative denial and the allow path.
func TestDecisionEvidenceCompleteness(t *testing.T) {
	cases := []struct {
		name string
		deps func(decision.Deps) decision.Deps
	}{
		{"allow", func(d decision.Deps) decision.Deps { return d }},
		{"deny", func(d decision.Deps) decision.Deps { d.Engine = fakeEngine{allowed: false}; return d }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decision.NewDecider(tc.deps(happyDeps())).Evaluate(context.Background(), companyRequest())
			if len(got.Evidence) == 0 {
				t.Fatalf("%s: no evidence attached", tc.name)
			}
			for _, e := range got.Evidence {
				if e.Key == "" {
					t.Fatalf("%s: evidence entry with empty key: %+v", tc.name, e)
				}
			}
		})
	}
}

// TestDecisionBatchMixedResults proves EvaluateBatch gives each item its own reason: two
// objects the engine allows/denies independently, within one otherwise-passing request.
func TestDecisionBatchMixedResults(t *testing.T) {
	deps := happyDeps()
	deps.Engine = &selectiveEngine{allow: map[string]bool{
		"company_module:company-1/test-module#viewer":  true,
		"company_module:company-1/other-module#viewer": false,
	}}
	base := companyRequest()
	base.RequiresEligibility = false
	items := []decision.BatchItem{
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/test-module"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/other-module"}, Relation: "viewer"},
	}
	results := decision.NewDecider(deps).EvaluateBatch(context.Background(), base, items)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if !results[0].Decision.Allowed || results[0].Decision.Reason != decision.ReasonAllowed {
		t.Fatalf("item 0: want allow, got %+v", results[0].Decision)
	}
	if results[1].Decision.Allowed || results[1].Decision.Reason != decision.ReasonEngineDenied {
		t.Fatalf("item 1: want ENGINE_DENIED, got %+v", results[1].Decision)
	}
}

type selectiveEngine struct {
	allow map[string]bool
}

func (s *selectiveEngine) Check(ctx context.Context, objType, objID, relation, subjType, subjID string) (bool, error) {
	key := objType + ":" + objID + "#" + relation
	return s.allow[key], nil
}

// TestDecisionAllReasonsCovered makes the coverage requirement explicit and countable: all
// 13 reasons must have been hit by SOME test above (order-independent — go test runs this last
// alphabetically isn't guaranteed, so it re-derives coverage from a dedicated table instead of
// relying on the package-level `coverage` map's build-up order across other tests).
func TestDecisionAllReasonsCovered(t *testing.T) {
	// Directly re-run one minimal case per reason so this test is self-contained and doesn't
	// depend on `go test` execution order populating the package-level `coverage` map first.
	cases := map[decision.Reason]func() decision.Decision{
		decision.ReasonAllowed: func() decision.Decision {
			return decision.NewDecider(happyDeps()).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonAuthUserNotFound: func() decision.Decision {
			deps := happyDeps()
			deps.Subject = fakeSubject{result: decision.SubjectResult{Found: false}}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonKeycloakDisabled: func() decision.Decision {
			deps := happyDeps()
			deps.Keycloak = fakeKeycloak{state: decision.KCFalse}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonUserLifecycleDisabled: func() decision.Decision {
			deps := happyDeps()
			deps.Subject = fakeSubject{result: decision.SubjectResult{Found: true, LifecycleActive: false}}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonCompanyInactive: func() decision.Decision {
			deps := happyDeps()
			deps.Company = fakeCompany{state: decision.CompanyState{Exists: true, Active: false}}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonCompanyMembershipRequired: func() decision.Decision {
			deps := happyDeps()
			deps.Membership = fakeMembership{state: decision.MembershipState{IsMember: false}}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonCompanyAccessBlocked: func() decision.Decision {
			deps := happyDeps()
			deps.Membership = fakeMembership{state: decision.MembershipState{IsMember: true, Blocked: true}}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonModuleDisabled: func() decision.Decision {
			deps := happyDeps()
			deps.ModuleState = fakeModuleState{enabled: false}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonPlatformRoleRequired: func() decision.Decision {
			deps := happyDeps()
			deps.PlatformRole = fakePlatformRole{has: false}
			return decision.NewDecider(deps).Evaluate(context.Background(), globalRequest())
		},
		decision.ReasonCompanyRoleRequired: func() decision.Decision {
			deps := happyDeps()
			deps.CompanyRole = fakeCompanyRole{has: false}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonEngineDenied: func() decision.Decision {
			deps := happyDeps()
			deps.Engine = fakeEngine{allowed: false}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonBusinessEligibilityDenied: func() decision.Decision {
			deps := happyDeps()
			deps.Eligibility = fakeEligibility{outcome: decision.EligibilityDenial}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
		decision.ReasonDependencyUnavailable: func() decision.Decision {
			deps := happyDeps()
			deps.Subject = fakeSubject{err: errors.New("boom")}
			return decision.NewDecider(deps).Evaluate(context.Background(), companyRequest())
		},
	}

	if len(cases) != len(decision.AllReasons) {
		t.Fatalf("this test covers %d reasons, decision.AllReasons has %d — keep them in sync", len(cases), len(decision.AllReasons))
	}

	covered := 0
	for _, want := range decision.AllReasons {
		fn, ok := cases[want]
		if !ok {
			t.Errorf("no case for reason %s", want)
			continue
		}
		got := fn()
		if got.Reason != want {
			t.Errorf("reason %s: got %s instead", want, got.Reason)
			continue
		}
		covered++
	}
	t.Logf("%d/%d reasons covered", covered, len(decision.AllReasons))
	if covered != len(decision.AllReasons) {
		t.Fatalf("only %d/%d reasons covered", covered, len(decision.AllReasons))
	}
}

func TestEligibilityWithoutSourceIsUnavailable(t *testing.T) {
	deps := happyDeps()
	deps.Eligibility = nil
	d := decision.NewDecider(deps)
	got := d.Evaluate(context.Background(), companyRequest())
	if got.Allowed || got.Reason != decision.ReasonDependencyUnavailable || got.Dependency != "module-eligibility" {
		t.Fatalf("got %+v, want DEPENDENCY_UNAVAILABLE on module-eligibility", got)
	}
	items := []decision.BatchItem{{Object: companyRequest().Object, Relation: "viewer"}}
	for _, r := range d.EvaluateBatch(context.Background(), companyRequest(), items) {
		if r.Decision.Allowed || r.Decision.Reason != decision.ReasonDependencyUnavailable {
			t.Fatalf("batch: got %+v, want DEPENDENCY_UNAVAILABLE", r.Decision)
		}
	}
}
