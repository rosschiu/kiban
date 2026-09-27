// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/engine"
	"github.com/rosschiu/kiban/internal/authz/fragment"
	"github.com/rosschiu/kiban/internal/authz/store"
)

// TestDecisionEngineRelationCheck_PositionHolderFlip proves the decision path the UI actually
// uses flips correctly when a position's holder changes. This exercises the EXACT SAME shape a module's real per-request tier check uses (helpdesk's
// AuthzClient.Can(featureTicketsWork) sets Object={company_module,<cid>/helpdesk}, Relation=
// "editor" — see modules/helpdesk/service/authzclient.go's relationLeg) end to end: org's REAL
// Store.AssignNow/EndAssignment grant/revoke the position-holder tuple, and
// decision.Decider.Evaluate — the SAME Decider handleSummary/handleCan both call — resolves
// through the full triangle (position#holder -> member#mapped_user -> user) with NO fakes in the
// engine leg. Zero additional authz calls happen between the two org-only fact changes (assign A,
// end A + assign B) — the "successor inherits the position's access" property.
func TestDecisionEngineRelationCheck_PositionHolderFlip(t *testing.T) {
	admin := adminPool(t)
	pool := authzPool(t)
	ctx := context.Background()

	orgFixture := newRealOrgFixture(t)
	kcSubA, kcSubB := "posacc-holder-a", "posacc-holder-b"
	companyID := seedCompanyAndMember(t, orgFixture, admin, "POSACCCO", "POSACCMA", kcSubA)

	// A second member, linked to kcSubB, in the SAME company (seedCompanyAndMember's own
	// registerCompanyCleanup already tears down every org.member row for this companyID).
	memberB, err := orgFixture.store.CreateMember(ctx, "test-actor", companyID, "POSACCMB", "Position Access Member B", "", true)
	if err != nil {
		t.Fatalf("create member B: %v", err)
	}
	mustCreateIdentityUserRow(t, admin, kcSubB)
	if _, err := orgFixture.store.LinkUser(ctx, "test-actor", noopIdentityChecker{}, memberB.ID, kcSubB); err != nil {
		t.Fatalf("link user B: %v", err)
	}
	// Registered AFTER mustCreateIdentityUserRow's own cleanup (t.Cleanup is LIFO — this runs
	// FIRST, deleting member B's row, which FKs to identity.user_account, BEFORE that row's own
	// delete runs) — otherwise the identity-user delete silently fails on a foreign_key_violation
	// (its own cleanup ignores the error) and leaves the kc_sub row behind for the next test run.
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = admin.Exec(ctx, `DELETE FROM org.position_assignment WHERE member_id = $1`, memberB.ID)
		_, _ = admin.Exec(ctx, `DELETE FROM org.member WHERE id = $1`, memberB.ID)
	})

	// The member linked to kcSubA from seedCompanyAndMember — resolve its id via org's own
	// company-facts read (the same one decision.MembershipSource uses) rather than re-deriving it.
	isMember, memberAID, _, err := orgFixture.store.MemberByCompanyAndKcSub(ctx, companyID, kcSubA)
	if err != nil || !isMember {
		t.Fatalf("resolve member A: isMember=%v err=%v", isMember, err)
	}

	position, err := orgFixture.store.CreatePosition(ctx, "test-actor", companyID, "POSACC", "Helpdesk Agent Seat", companyID)
	if err != nil {
		t.Fatalf("create position: %v", err)
	}

	moduleObjectID := companyID.String() + "/posaccmod"
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, moduleObjectID)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_type='company_module' AND object_id=$1`, moduleObjectID)
	})
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-actor", "posacc-corr", store.Tuple{
		ObjectType: "company_module", ObjectID: moduleObjectID, Relation: "editor",
		SubjectType: "position", SubjectID: position.ID.String(), SubjectRelation: "holder",
	}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant company_module#editor @ position#holder: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	loaded, err := fragment.Load(ctx, pool, map[string]bool{})
	if err != nil {
		t.Fatalf("fragment.Load: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: loaded.Model}
	checker := fragmentEngineChecker{en: en, loaded: loaded}
	orgClient := NewOrgClient(&http.Client{Timeout: 2 * time.Second}, orgFixture.orgURL)

	evaluateFor := func(kcSub string) decision.Decision {
		deps := decision.Deps{
			Subject:      fakeSubject{result: decision.SubjectResult{Found: true, LifecycleActive: true}},
			Keycloak:     fakeKeycloak{state: decision.KCTrue},
			PlatformRole: fakePlatformRole{has: false},
			Company:      orgClient,
			Membership:   orgClient,
			CompanyRole:  engineCompanyRoleSource{checker: checker},
			ModuleState:  fakeModuleState{enabled: true},
			Engine:       checker,
		}
		req := decision.Request{
			SubjectID:  kcSub,
			FeatureKey: "posaccmod.tickets.work",
			ModuleKey:  "posaccmod",
			Scope:      decision.ScopeCompany,
			CompanyID:  companyID.String(),
			Object:     decision.ObjectRef{Type: "company_module", ID: moduleObjectID},
			Relation:   "editor",
		}
		return decision.NewDecider(deps).Evaluate(ctx, req)
	}

	// Nobody holds the position yet: neither kcSub resolves the tier.
	if got := evaluateFor(kcSubA); got.Allowed {
		t.Fatalf("kcSubA: want DENIED before any assignment, got reason=%s", got.Reason)
	}

	// Assign A — org's own fact-layer call (Store.AssignNow) grants the holder tuple
	// transactionally; no separate authz call.
	assignmentA, err := orgFixture.store.AssignNow(ctx, "test-actor", position.ID, memberAID)
	if err != nil {
		t.Fatalf("assign A: %v", err)
	}
	if got := evaluateFor(kcSubA); !got.Allowed || got.Reason != decision.ReasonAllowed {
		t.Fatalf("kcSubA: want ALLOWED while holding the bound position, got reason=%s evidence=%+v", got.Reason, got.Evidence)
	}
	if got := evaluateFor(kcSubB); got.Allowed {
		t.Fatalf("kcSubB: want DENIED before holding the position, got reason=%s", got.Reason)
	}

	// End A + assign B — the same-day handover case. Zero authz calls between these
	// two org-only fact changes.
	if _, err := orgFixture.store.EndAssignment(ctx, "test-actor", assignmentA.ID); err != nil {
		t.Fatalf("end A: %v", err)
	}
	if _, err := orgFixture.store.AssignNow(ctx, "test-actor", position.ID, memberB.ID); err != nil {
		t.Fatalf("assign B: %v", err)
	}

	if got := evaluateFor(kcSubA); got.Allowed {
		t.Fatalf("kcSubA: want DENIED after the handover, got reason=%s", got.Reason)
	}
	if got := evaluateFor(kcSubB); !got.Allowed || got.Reason != decision.ReasonAllowed {
		t.Fatalf("kcSubB: want ALLOWED as the position's new holder, got reason=%s evidence=%+v", got.Reason, got.Evidence)
	}
}
