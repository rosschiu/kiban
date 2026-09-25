// SPDX-License-Identifier: Apache-2.0

// Package decision implements the effective-access decision EXACTLY: the ordered
// 8-step, fail-closed effective-access decision, the 13-reason enum (OPENFGA_DENIED is named
// ENGINE_DENIED here — the engine is not OpenFGA), and evidence/batchCan semantics. Every
// dependency is injected as a small interface so unit tests can fake each upstream
// independently; internal/authz wires real HTTP/engine implementations.
//
// No decision is ever cached (EA-D7): every call re-derives the answer from its
// dependencies. A dependency's own uncertainty (a non-nil error, or a tri-state "unknown")
// always maps to DEPENDENCY_UNAVAILABLE — it never falls through to allow at a later step.
package decision

import (
	"context"
	"time"
)

// Reason is one of the 13 frozen effective-access reason codes (verbatim from
// the effective-access decision, with OPENFGA_DENIED renamed ENGINE_DENIED).
type Reason string

const (
	ReasonAllowed                   Reason = "ALLOWED"
	ReasonAuthUserNotFound          Reason = "AUTH_USER_NOT_FOUND"
	ReasonKeycloakDisabled          Reason = "KEYCLOAK_DISABLED"
	ReasonUserLifecycleDisabled     Reason = "USER_LIFECYCLE_DISABLED"
	ReasonCompanyInactive           Reason = "COMPANY_INACTIVE"
	ReasonCompanyMembershipRequired Reason = "COMPANY_MEMBERSHIP_REQUIRED"
	ReasonCompanyAccessBlocked      Reason = "COMPANY_ACCESS_BLOCKED"
	ReasonModuleDisabled            Reason = "MODULE_DISABLED"
	ReasonPlatformRoleRequired      Reason = "PLATFORM_ROLE_REQUIRED"
	ReasonCompanyRoleRequired       Reason = "COMPANY_ROLE_REQUIRED"
	ReasonEngineDenied              Reason = "ENGINE_DENIED" // was OPENFGA_DENIED in the contract
	ReasonBusinessEligibilityDenied Reason = "BUSINESS_ELIGIBILITY_DENIED"
	ReasonDependencyUnavailable     Reason = "DEPENDENCY_UNAVAILABLE"
)

// AllReasons lists all 13 codes, for tests that must prove full coverage.
var AllReasons = []Reason{
	ReasonAllowed, ReasonAuthUserNotFound, ReasonKeycloakDisabled, ReasonUserLifecycleDisabled,
	ReasonCompanyInactive, ReasonCompanyMembershipRequired, ReasonCompanyAccessBlocked,
	ReasonModuleDisabled, ReasonPlatformRoleRequired, ReasonCompanyRoleRequired,
	ReasonEngineDenied, ReasonBusinessEligibilityDenied, ReasonDependencyUnavailable,
}

// Evidence is one fact the decision was based on, attached regardless of outcome (EA-D6/D7).
type Evidence struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Decision is the outcome of one Evaluate call. A denial is Allowed=false with a non-ALLOWED
// Reason — never an HTTP error (the enforcement boundary in internal/authz's HTTP layer is
// responsible for the 200-vs-503 mapping: 503 only for DEPENDENCY_UNAVAILABLE).
type Decision struct {
	Allowed    bool
	Reason     Reason
	Evidence   []Evidence
	Dependency string // set only when Reason == DEPENDENCY_UNAVAILABLE (EA-D6 telemetry)
	Step       string // set only when Reason == DEPENDENCY_UNAVAILABLE (EA-D6 telemetry)
}

func deny(reason Reason, ev *[]Evidence, kv ...string) Decision {
	appendEvidence(ev, kv...)
	return Decision{Allowed: false, Reason: reason, Evidence: *ev}
}

func unavailable(dependency, step string, ev *[]Evidence) Decision {
	appendEvidence(ev, "dependency", dependency, "step", step)
	return Decision{Allowed: false, Reason: ReasonDependencyUnavailable, Evidence: *ev, Dependency: dependency, Step: step}
}

func allow(ev *[]Evidence, kv ...string) Decision {
	appendEvidence(ev, kv...)
	return Decision{Allowed: true, Reason: ReasonAllowed, Evidence: *ev}
}

func appendEvidence(ev *[]Evidence, kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		*ev = append(*ev, Evidence{Key: kv[i], Value: kv[i+1]})
	}
}

// --- Dependency interfaces (tests fake each of these; internal/authz wires real clients) ---

// SubjectResult is step 1's outcome.
type SubjectResult struct {
	Found           bool
	LifecycleActive bool
}

// SubjectSource resolves the subject's identity.user_account row (step 1/3).
type SubjectSource interface {
	Lookup(ctx context.Context, subjectID string) (SubjectResult, error)
}

// KCState mirrors identity.KCStateTrue/False/Unknown (step 2) — kept as an independent type so
// this package never imports internal/identity (no platform-code-to-module-code direction
// violation).
type KCState string

const (
	KCTrue    KCState = "true"
	KCFalse   KCState = "false"
	KCUnknown KCState = "unknown"
)

// KeycloakSource reports the LIVE Keycloak-enabled tri-state (step 2). A non-nil error and
// KCUnknown are handled identically by Evaluate (both ⇒ DEPENDENCY_UNAVAILABLE) — never
// defaulted to enabled.
type KeycloakSource interface {
	Enabled(ctx context.Context, subjectID string) (KCState, error)
}

// PlatformRoleSource answers whether a subject holds a named platform role (steps 4 and the
// operator exception in step 5). JWT roles are NEVER an acceptable implementation — this must
// be backed by a live DB read (the effective-access decision's closing invariant).
type PlatformRoleSource interface {
	HasRole(ctx context.Context, subjectID, role string) (bool, error)
}

// CompanyState is step 5's company-existence/activity outcome.
type CompanyState struct {
	Exists bool
	Active bool
}

// CompanySource reports company state (step 5).
type CompanySource interface {
	State(ctx context.Context, companyID string) (CompanyState, error)
}

// MembershipState is step 5's membership outcome.
type MembershipState struct {
	IsMember bool
	Blocked  bool
}

// MembershipSource reports company membership (step 5).
type MembershipSource interface {
	Membership(ctx context.Context, companyID, subjectID string) (MembershipState, error)
}

// CompanyRoleSource answers whether a subject holds a named company-scoped role (step 5's
// COMPANY_ROLE_REQUIRED leg).
type CompanyRoleSource interface {
	HasRole(ctx context.Context, companyID, subjectID, role string) (bool, error)
}

// ModuleStateSource reports whether a module is installed+enabled (step 6; registry
// capability — MODULE_DISABLED covers both "not installed" and "disabled" at this decision's
// granularity, per the reason enum having no separate NOT_INSTALLED code).
type ModuleStateSource interface {
	Enabled(ctx context.Context, moduleKey string) (bool, error)
}

// EngineChecker is the relation check (step 7 — internal/authz/engine.Engine.Check satisfies
// this directly).
type EngineChecker interface {
	Check(ctx context.Context, objType, objID, relation, subjType, subjID string) (bool, error)
}

// RelationDefiner answers whether the EFFECTIVE model (base + enabled fragments) defines
// relation on objType — the step-7 company-binding rule is model-driven: an object type
// that defines `company` binds through `company`, one that defines `company_module` binds
// through its module anchor, one that defines neither cannot be bound and is denied.
// fragmentEngineChecker in internal/authz satisfies this from the loaded model.
type RelationDefiner interface {
	Defines(objType, relation string) bool
}

// EligibilityOutcome is the module eligibility callback's tri-state result (EA-D11): DENIAL is
// a business no (⇒ BUSINESS_ELIGIBILITY_DENIED), ERROR means the module's own dependency broke
// (⇒ DEPENDENCY_UNAVAILABLE) — the callback itself distinguishes these, Evaluate never guesses.
type EligibilityOutcome int

const (
	EligibilityAllow EligibilityOutcome = iota
	EligibilityDenial
	EligibilityError
)

// EligibilityCallback is the optional module-owned business-eligibility check (step 8,
// accessRuleKind "module_eligibility"). Non-cacheable per EA-D11; Evaluate enforces the 2s
// timeout itself so no implementation can accidentally skip it.
type EligibilityCallback interface {
	CheckEligibility(ctx context.Context, req Request) (EligibilityOutcome, error)
}

// ObjectRef is the (type,id) pair the engine check (step 7) runs against.
type ObjectRef struct {
	Type string
	ID   string
}

// Scope selects whether Evaluate runs the step-4 global-role path or the step-5 company path.
type Scope string

const (
	ScopeGlobal  Scope = "global"
	ScopeCompany Scope = "company"
)

// Request is one effective-access question. SubjectID is ALWAYS the validated bearer subject
// (kcSub) — Forbidden: never accept an actor from a request body.
type Request struct {
	SubjectID  string
	FeatureKey string
	ModuleKey  string
	Scope      Scope
	CompanyID  string // required when Scope == ScopeCompany

	// Step 4 (global) / step 5 operator-exception role name.
	RequiredPlatformRole string
	// AllowPlatformOperatorCompanyScope opts a company-scope request into the named,
	// auditable escape hatch: an operator holding RequiredPlatformRole skips the membership
	// requirement (never a fabricated membership) but the company must still be active.
	AllowPlatformOperatorCompanyScope bool
	// RequiredCompanyRole, when set, is checked after membership (step 5's
	// COMPANY_ROLE_REQUIRED leg).
	RequiredCompanyRole string

	// Step 7: the relation check. Skipped (treated as satisfied) when Relation == "" — some
	// features are pure role/eligibility gates with no object-relation leg.
	Object   ObjectRef
	Relation string

	// Step 8: business eligibility. Skipped when RequiresEligibility is false.
	RequiresEligibility bool

	CorrelationID string
}

// Deps bundles every dependency Evaluate needs. Any nil field that a request path would reach
// is a programmer error (panics) — the real Decider is always constructed with all seven
// wired.
type Deps struct {
	Subject      SubjectSource
	Keycloak     KeycloakSource
	PlatformRole PlatformRoleSource
	Company      CompanySource
	Membership   MembershipSource
	CompanyRole  CompanyRoleSource
	ModuleState  ModuleStateSource
	Engine       EngineChecker
	Model        RelationDefiner     // nil ⇒ no module/base object can be bound (fail closed); only company/company_module fast paths remain
	Eligibility  EligibilityCallback // may be nil when no request ever sets RequiresEligibility

	// EligibilityTimeout overrides the EA-D11 2s default — test-only; zero means 2s.
	EligibilityTimeout time.Duration
}
