// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/engine"
	"github.com/rosschiu/kiban/internal/authz/fragment"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/livestack"
	"github.com/rosschiu/kiban/internal/org"
)

// --- Real (non-faked) org/engine wiring, on top of decision_test.go's fake-based coverage —
// proves the un-stubbed CompanySource/MembershipSource/CompanyRoleSource paths, not just
// decision.Evaluate's branching logic. ---

// fakeOrgUnreachableServer answers every request with a transport-level failure by closing
// immediately — used to prove a genuinely unreachable org collapses to DEPENDENCY_UNAVAILABLE,
// never a guessed allow/deny (mirrors clients_test.go's real-client style).
func fakeOrgUnreachableServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // closed before any client dials it: every request errors at transport level
	return srv
}

// orgTestPool connects as kiban_org (the real runtime role) so this file's fixtures use
// the same grants the org service runs with in production — same testEnv/loadTestEnv plumbing
// grant_test.go's authzPool/adminPool already establish in this package.
func orgTestPool(t *testing.T) *pgxpool.Pool {
	return livestack.Pool(t, "kiban_org", testEnv(t, "KIBAN_ORG_DB_PASSWORD"))
}

// realOrgFixture wires a real org.Store (live DB) behind a real org.Service HTTP server — the
// company-facts GET endpoints are open reads (no AdminAuthorizer gate), so they're exercised
// over a genuine HTTP round trip via OrgClient below. Mutations (create company/member/link) go
// straight through the store, bypassing org's HTTP mutation layer, which is wired fail-closed
// (denyAllAuthorizer) here — the same "call the store directly to seed fixtures" pattern
// internal/org's own tests use (internal/org/test_helpers_test.go's mustCreateCompany et al.).
type realOrgFixture struct {
	store  *org.Store
	orgURL string
}

func newRealOrgFixture(t *testing.T) *realOrgFixture {
	t.Helper()
	pool := orgTestPool(t)
	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		t.Fatalf("build org audit writer: %v", err)
	}
	orgStore := org.NewStore(pool, auditWriter)
	svc := org.NewService(orgStore, noopIdentityChecker{}, org.NewDenyAllAuthorizer(), auditWriter)
	srv := httptest.NewServer(svc.Routes())
	t.Cleanup(srv.Close)
	return &realOrgFixture{store: orgStore, orgURL: srv.URL}
}

type noopIdentityChecker struct{}

func (noopIdentityChecker) UserExists(ctx context.Context, kcSub string) (bool, error) {
	return true, nil
}

// mustCreateIdentityUserRow inserts a minimal identity.user_account row directly (org's own
// tests do the same — org's store has no write path into identity's schema) so the
// company-facts membership join (identity.user_read_v) has something to resolve. Registers its
// own teardown so re-running this file's tests against the shared dev database never collides
// on kc_sub's implicit uniqueness.
func mustCreateIdentityUserRow(t *testing.T, admin *pgxpool.Pool, kcSub string) {
	t.Helper()
	_, err := admin.Exec(context.Background(),
		`INSERT INTO identity.user_account (kc_sub, email, preferred_username) VALUES ($1, $2, $3)`,
		kcSub, kcSub+"@example.com", kcSub)
	if err != nil {
		t.Fatalf("create identity user %s: %v", kcSub, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM identity.user_account WHERE kc_sub = $1`, kcSub)
	})
}

// registerCompanyCleanup tears down a company org_unit and everything that references it
// (members, and any position/assignment rows a test might have added) at test end — this
// file's fixtures run against the SAME live dev database org's own tests use, so leaving rows
// behind would make re-running `go test` (no fixture reset between runs, unlike
// internal/org's resetOrgFixtures) fail the next run's UNIQUE(code) constraints.
func registerCompanyCleanup(t *testing.T, admin *pgxpool.Pool, companyID uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = admin.Exec(ctx, `DELETE FROM org.position_assignment WHERE member_id IN (SELECT id FROM org.member WHERE company_id = $1)`, companyID)
		_, _ = admin.Exec(ctx, `DELETE FROM org.position WHERE company_id = $1`, companyID)
		_, _ = admin.Exec(ctx, `DELETE FROM org.member WHERE company_id = $1`, companyID)
		_, _ = admin.Exec(ctx, `DELETE FROM org.org_unit WHERE id = $1`, companyID)
	})
}

// seedCompanyAndMember creates a company + an active member linked to kcSub, entirely via the
// real org.Store against the live dev database, returning the company's id. Registers cleanup
// for every row it creates — the company/member cleanup is registered LAST (after the identity
// user's), so t.Cleanup's LIFO order deletes org.member (which FKs to identity.user_account)
// BEFORE the identity user row, avoiding a foreign_key_violation on teardown.
func seedCompanyAndMember(t *testing.T, f *realOrgFixture, admin *pgxpool.Pool, companyCode, memberCode, kcSub string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	company, err := f.store.CreateOrgUnit(ctx, "test-actor", "company", nil, companyCode, "Company Scope Co "+companyCode, true)
	if err != nil {
		t.Fatalf("create company: %v", err)
	}
	member, err := f.store.CreateMember(ctx, "test-actor", company.ID, memberCode, "Company Scope Member", "", true)
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	mustCreateIdentityUserRow(t, admin, kcSub)
	if _, err := f.store.LinkUser(ctx, "test-actor", noopIdentityChecker{}, member.ID, kcSub); err != nil {
		t.Fatalf("link user: %v", err)
	}
	registerCompanyCleanup(t, admin, company.ID)
	return company.ID
}

func TestDecisionCompanyStateWiredToOrgInactive(t *testing.T) {
	admin := adminPool(t)
	f := newRealOrgFixture(t)
	ctx := context.Background()
	unit, err := f.store.CreateOrgUnit(ctx, "test-actor", "company", nil, "SCOPEINACT", "Inactive Co", false)
	if err != nil {
		t.Fatalf("create inactive company: %v", err)
	}
	registerCompanyCleanup(t, admin, unit.ID)

	client := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	deps := happyDeps()
	deps.Company = client
	deps.Membership = client
	req := companyRequest()
	req.CompanyID = unit.ID.String()
	req.RequiredCompanyRole = ""

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Reason != decision.ReasonCompanyInactive {
		t.Fatalf("reason = %s, want COMPANY_INACTIVE (evidence=%+v)", got.Reason, got.Evidence)
	}
}

func TestDecisionCompanyStateWiredToOrgUnknownID(t *testing.T) {
	f := newRealOrgFixture(t)
	client := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	deps := happyDeps()
	deps.Company = client
	deps.Membership = client
	req := companyRequest()
	req.CompanyID = uuid.New().String()
	req.RequiredCompanyRole = ""

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Reason != decision.ReasonCompanyInactive {
		t.Fatalf("reason = %s, want COMPANY_INACTIVE for an unknown company id (evidence=%+v)", got.Reason, got.Evidence)
	}
}

func TestDecisionCompanyMembershipWiredToOrgRequired(t *testing.T) {
	admin := adminPool(t)
	f := newRealOrgFixture(t)
	ctx := context.Background()
	company, err := f.store.CreateOrgUnit(ctx, "test-actor", "company", nil, "SCOPENOMEM", "No Member Co", true)
	if err != nil {
		t.Fatalf("create company: %v", err)
	}
	registerCompanyCleanup(t, admin, company.ID)

	client := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	deps := happyDeps()
	deps.Company = client
	deps.Membership = client
	req := companyRequest()
	req.CompanyID = company.ID.String()
	req.SubjectID = "scope-nomember-kcsub"
	req.RequiredCompanyRole = ""

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Reason != decision.ReasonCompanyMembershipRequired {
		t.Fatalf("reason = %s, want COMPANY_MEMBERSHIP_REQUIRED (evidence=%+v)", got.Reason, got.Evidence)
	}
}

func TestDecisionCompanyAccessBlockedWiredToOrg(t *testing.T) {
	admin := adminPool(t)
	f := newRealOrgFixture(t)
	kcSub := "scope-blocked-kcsub"
	companyID := seedCompanyAndMember(t, f, admin, "SCOPEBLOCK", "SCOPEBLKM", kcSub)

	// Deactivate the member — the v1 COMPANY_ACCESS_BLOCKED source.
	members, _, err := f.store.ListMembers(context.Background(), companyID, 1, 10)
	if err != nil || len(members) == 0 {
		t.Fatalf("list members: %v (n=%d)", err, len(members))
	}
	if _, err := f.store.UpdateMember(context.Background(), "test-actor", members[0].ID, members[0].DisplayName, members[0].Email, false); err != nil {
		t.Fatalf("deactivate member: %v", err)
	}

	client := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	deps := happyDeps()
	deps.Company = client
	deps.Membership = client
	req := companyRequest()
	req.CompanyID = companyID.String()
	req.SubjectID = kcSub
	req.RequiredCompanyRole = ""

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Reason != decision.ReasonCompanyAccessBlocked {
		t.Fatalf("reason = %s, want COMPANY_ACCESS_BLOCKED (evidence=%+v)", got.Reason, got.Evidence)
	}
}

func TestDecisionCompanyMembershipWiredToOrgAllowed(t *testing.T) {
	admin := adminPool(t)
	f := newRealOrgFixture(t)
	kcSub := "scope-active-kcsub"
	companyID := seedCompanyAndMember(t, f, admin, "SCOPEACTIVE", "SCOPEACTM", kcSub)

	client := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	deps := happyDeps()
	deps.Company = client
	deps.Membership = client
	req := companyRequest()
	req.CompanyID = companyID.String()
	req.Object.ID = req.CompanyID + "/test-module" // step 7 binds the object to the request's company
	req.SubjectID = kcSub
	req.RequiredCompanyRole = "" // step 5 role leg unrelated to this test; engine stays faked

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if !got.Allowed || got.Reason != decision.ReasonAllowed {
		t.Fatalf("want ALLOWED for an active member of an active company, got reason=%s evidence=%+v", got.Reason, got.Evidence)
	}
}

// TestDecisionOrgUnreachableCompanyState / ...Membership prove a genuinely unreachable org
// collapses to DEPENDENCY_UNAVAILABLE (dependency "org") at both step-5 legs, never a fabricated
// allow — the fail-closed guarantee.
func TestDecisionOrgUnreachableCompanyState(t *testing.T) {
	srv := fakeOrgUnreachableServer(t)
	client := NewOrgClient(&http.Client{Timeout: 500 * time.Millisecond}, srv.URL)
	deps := happyDeps()
	deps.Company = client
	req := companyRequest()

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Allowed {
		t.Fatalf("unreachable org must never allow, got %+v", got)
	}
	if got.Reason != decision.ReasonDependencyUnavailable || got.Dependency != "org" {
		t.Fatalf("reason=%s dependency=%q, want DEPENDENCY_UNAVAILABLE/org", got.Reason, got.Dependency)
	}
}

func TestDecisionOrgUnreachableMembership(t *testing.T) {
	srv := fakeOrgUnreachableServer(t)
	client := NewOrgClient(&http.Client{Timeout: 500 * time.Millisecond}, srv.URL)
	deps := happyDeps()
	deps.Company = fakeCompany{state: decision.CompanyState{Exists: true, Active: true}}
	deps.Membership = client
	req := companyRequest()

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if got.Allowed {
		t.Fatalf("unreachable org must never allow, got %+v", got)
	}
	if got.Reason != decision.ReasonDependencyUnavailable || got.Dependency != "org" {
		t.Fatalf("reason=%s dependency=%q, want DEPENDENCY_UNAVAILABLE/org", got.Reason, got.Dependency)
	}
}

// TestDecisionOperatorExceptionWiredToOrgSkipsMembership proves the operator exception (the
// explicit allowPlatformOperatorCompanyScope exception — no fabricated memberships) still
// works with a REAL OrgClient in the loop: Membership is wired to a server that would
// error if ever called, proving it genuinely isn't.
func TestDecisionOperatorExceptionWiredToOrgSkipsMembership(t *testing.T) {
	admin := adminPool(t)
	f := newRealOrgFixture(t)
	ctx := context.Background()
	company, err := f.store.CreateOrgUnit(ctx, "test-actor", "company", nil, "SCOPEOPEXC", "Operator Co", true)
	if err != nil {
		t.Fatalf("create company: %v", err)
	}
	registerCompanyCleanup(t, admin, company.ID)

	companyClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, f.orgURL)
	membershipMustNotBeCalled := NewOrgClient(&http.Client{Timeout: 500 * time.Millisecond}, fakeOrgUnreachableServer(t).URL)

	deps := happyDeps()
	deps.Company = companyClient
	deps.Membership = membershipMustNotBeCalled
	req := companyRequest()
	req.CompanyID = company.ID.String()
	req.Object.ID = req.CompanyID + "/test-module" // step 7 binds the object to the request's company
	req.AllowPlatformOperatorCompanyScope = true
	req.RequiredPlatformRole = "kiban-superadmin"
	req.RequiredCompanyRole = ""

	got := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if !got.Allowed {
		t.Fatalf("platform-operator exception should allow without ever calling the (unreachable) Membership source: %+v", got)
	}
}

// TestDecisionCompanyRoleWiredToEngine proves decision.CompanyRoleSource's v1 implementation
// (engineCompanyRoleSource) is a real `company:<id>#<role>` tuple check, not a fake — using the
// real fragment-loaded engine against the live authz database (an engine tuple check on
// company:<id> relations, authz-side only).
func TestDecisionCompanyRoleWiredToEngine(t *testing.T) {
	pool := authzPool(t)
	ctx := context.Background()
	// "company" is a platform BASE type, always loaded (internal/authz/engine.BaseModel) — #admin
	// is resolvable via "this" (among other branches) with zero module fragments, so this test
	// installs no synthetic "company" model fragment (the base-type-redeclaration reject would
	// refuse one anyway).

	companyID := "role-company"
	adminSubject := "role-admin"
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id = $1`, companyID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "role-corr", store.Tuple{
		ObjectType: "company", ObjectID: companyID, Relation: "admin", SubjectType: "user", SubjectID: adminSubject,
	}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, companyID)
	})

	loaded, err := fragment.Load(ctx, pool, map[string]bool{})
	if err != nil {
		t.Fatalf("fragment.Load: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: loaded.Model}
	roleSource := engineCompanyRoleSource{checker: fragmentEngineChecker{en: en, loaded: loaded}}

	t.Run("granted subject has the role", func(t *testing.T) {
		has, err := roleSource.HasRole(ctx, companyID, adminSubject, "admin")
		if err != nil {
			t.Fatalf("HasRole: %v", err)
		}
		if !has {
			t.Fatalf("want has=true for the granted subject")
		}
	})

	t.Run("un-granted subject does not have the role", func(t *testing.T) {
		has, err := roleSource.HasRole(ctx, companyID, "role-someone-else", "admin")
		if err != nil {
			t.Fatalf("HasRole: %v", err)
		}
		if has {
			t.Fatalf("want has=false for an un-granted subject")
		}
	})

	// End-to-end through decision.Evaluate: happy company-scope deps except CompanyRole is the
	// REAL engine-backed source above.
	deps := happyDeps()
	deps.CompanyRole = roleSource
	req := companyRequest()
	req.CompanyID = companyID
	req.Object.ID = companyID + "/test-module" // step 7 binds the object to the request's company
	req.SubjectID = adminSubject
	req.RequiredCompanyRole = "admin"

	got := decision.NewDecider(deps).Evaluate(ctx, req)
	if !got.Allowed || got.Reason != decision.ReasonAllowed {
		t.Fatalf("want ALLOWED via the real engine-backed CompanyRoleSource, got reason=%s evidence=%+v", got.Reason, got.Evidence)
	}

	deps2 := happyDeps()
	deps2.CompanyRole = roleSource
	req2 := req
	req2.SubjectID = "role-someone-else"
	got2 := decision.NewDecider(deps2).Evaluate(ctx, req2)
	if got2.Reason != decision.ReasonCompanyRoleRequired {
		t.Fatalf("reason = %s, want COMPANY_ROLE_REQUIRED for an un-granted subject", got2.Reason)
	}
}

// TestDecisionCompanyScopeEndToEndAllowed is the end-to-end proof: a
// company + member seeded via org's real store, a tuple granted via authz's real transactional
// Grant, and a full decision.Evaluate() using ONLY the production adapters this run wires
// (OrgClient for Company/Membership, engineCompanyRoleSource + the real fragment-loaded engine
// for the object-relation check) — no fakes anywhere in the company-scope leg — resolving to
// ALLOWED.
func TestDecisionCompanyScopeEndToEndAllowed(t *testing.T) {
	admin := adminPool(t)
	pool := authzPool(t)
	ctx := context.Background()

	orgFixture := newRealOrgFixture(t)
	kcSub := "role-e2e-kcsub"
	companyID := seedCompanyAndMember(t, orgFixture, admin, "SCOPEE2ECO", "SCOPEE2EM", kcSub)

	// "company" is a platform BASE type, always loaded (internal/authz/engine.BaseModel) — #admin
	// is resolvable via "this" (among other branches) with zero module fragments, so this test
	// installs no synthetic "company" model fragment (the base-type-redeclaration reject would
	// refuse one anyway).
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id = $1`, companyID.String())
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "role-e2e-corr", store.Tuple{
		ObjectType: "company", ObjectID: companyID.String(), Relation: "admin", SubjectType: "user", SubjectID: kcSub,
	}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, companyID.String())
	})

	loaded, err := fragment.Load(ctx, pool, map[string]bool{})
	if err != nil {
		t.Fatalf("fragment.Load: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: loaded.Model}
	checker := fragmentEngineChecker{en: en, loaded: loaded}
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, orgFixture.orgURL)

	deps := decision.Deps{
		Subject:      fakeSubject{result: decision.SubjectResult{Found: true, LifecycleActive: true}},
		Keycloak:     fakeKeycloak{state: decision.KCTrue},
		PlatformRole: fakePlatformRole{has: false}, // not the operator-exception path
		Company:      orgClient,
		Membership:   orgClient,
		CompanyRole:  engineCompanyRoleSource{checker: checker},
		ModuleState:  fakeModuleState{enabled: true},
		Engine:       checker,
	}
	req := decision.Request{
		SubjectID:           kcSub,
		FeatureKey:          "test.e2e.company_scope",
		ModuleKey:           "test-module",
		Scope:               decision.ScopeCompany,
		CompanyID:           companyID.String(),
		RequiredCompanyRole: "admin",
		Object:              decision.ObjectRef{Type: "company", ID: companyID.String()},
		Relation:            "admin",
	}

	got := decision.NewDecider(deps).Evaluate(ctx, req)
	if !got.Allowed || got.Reason != decision.ReasonAllowed {
		t.Fatalf("want ALLOWED end-to-end (org-seeded company+member, authz-granted tuple), got reason=%s evidence=%+v", got.Reason, got.Evidence)
	}
}

func mustExecAuthz(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
