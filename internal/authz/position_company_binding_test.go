// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
)

// TestLive_PositionBoundToRequestCompany is the live proof for the helpdesk shape:
// helpdesk's IsPositionHolder is exactly this request —
// `position:<id>#holder @ user:<caller>` at company scope with the URL company. A position
// created in company A (org writes `position:<id>#company @ company:A`) whose holder is a
// member of both companies is denied through company B's path with `objectCompany=false`
// (the decision helpdesk maps to 403 on a B-path ticket assigned to A's position) and allowed
// through A. The holder tuple is real and would have allowed before the binding.
func TestLive_PositionBoundToRequestCompany(t *testing.T) {
	const (
		moduleKey = "helpdesk-bind-carrier"
		companyA  = "bind-pos-company-a"
		companyB  = "bind-pos-company-b"
		holderSub = "bind-pos-holder-sub"
		memberID  = "bind-pos-member"
		positionA = "bind-position-in-a"
	)
	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{holderSub: nil},
		map[string]bool{moduleKey: true},
		map[string]fakeCompanyFact{companyA: {exists: true, active: true}, companyB: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyA + "/" + holderSub: {isMember: true, active: true},
			companyB + "/" + holderSub: {isMember: true, active: true},
		},
		false,
	)
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ($1, $2)`, positionA, memberID)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id IN ($1, $2)`, positionA, memberID)
	})
	// The org-written shape: position anchored to A, holder via member#mapped_user -> user.
	grantTestTuple(t, pool, store.Tuple{ObjectType: "position", ObjectID: positionA, Relation: "company", SubjectType: "company", SubjectID: companyA})
	grantTestTuple(t, pool, store.Tuple{ObjectType: "position", ObjectID: positionA, Relation: "holder", SubjectType: "member", SubjectID: memberID, SubjectRelation: "mapped_user"})
	grantTestTuple(t, pool, store.Tuple{ObjectType: "member", ObjectID: memberID, Relation: "mapped_user", SubjectType: "user", SubjectID: holderSub})

	can := func(t *testing.T, companyID string) (bool, string, []decision.Evidence) {
		t.Helper()
		body := mustJSON(t, map[string]any{
			"featureKey": "helpdesk.tickets.work", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID,
			"object":    map[string]string{"type": "position", "id": positionA},
			"relation":  "holder",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, holderSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var out struct {
			Data struct {
				Allowed  bool                `json:"allowed"`
				Reason   string              `json:"reason"`
				Evidence []decision.Evidence `json:"evidence"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		return out.Data.Allowed, out.Data.Reason, out.Data.Evidence
	}

	t.Run("through company A (the position's company): holder allowed", func(t *testing.T) {
		allowed, reason, ev := can(t, companyA)
		if !allowed || reason != "ALLOWED" {
			t.Fatalf("allowed=%v reason=%s ev=%+v, want ALLOWED", allowed, reason, ev)
		}
		if v, _ := evidenceValue(ev, "objectCompany"); v != "true" {
			t.Fatalf("objectCompany evidence = %q, want true", v)
		}
	})

	t.Run("through company B: ENGINE_DENIED objectCompany=false, holder never evaluated", func(t *testing.T) {
		allowed, reason, ev := can(t, companyB)
		if allowed || reason != "ENGINE_DENIED" {
			t.Fatalf("allowed=%v reason=%s ev=%+v, want ENGINE_DENIED", allowed, reason, ev)
		}
		if v, _ := evidenceValue(ev, "objectCompany"); v != "false" {
			t.Fatalf("objectCompany evidence = %q, want false (ev=%+v)", v, ev)
		}
		if _, ok := evidenceValue(ev, "relation"); ok {
			t.Fatalf("relation must not be evaluated after a failed binding: %+v", ev)
		}
	})
}
