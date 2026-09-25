// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// TestLive_ObjectBoundToRequestCompany is the live proof of the company-binding rule through
// the REAL `/internal/authz/effective-access/can` endpoint: a document created (anchored) in
// company B, whose owner is an active member of both A and B, is denied through company A's
// path with `objectCompany=false` in the evidence — the decision a module maps to 403 — while
// company B's own path still answers ALLOWED. The relation tuple is real and would have allowed
// before the binding; only the anchor mismatch denies.
func TestLive_ObjectBoundToRequestCompany(t *testing.T) {
	const (
		moduleKey = "bind-docs-carrier"
		fragMod   = "bind-docs-mod"
		companyA  = "bind-company-a"
		companyB  = "bind-company-b"
		ownerSub  = "bind-owner-sub"
		docB      = "bind-doc-in-b"
	)
	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{ownerSub: nil},
		map[string]bool{moduleKey: true, fragMod: true},
		map[string]fakeCompanyFact{companyA: {exists: true, active: true}, companyB: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyA + "/" + ownerSub: {isMember: true, active: true},
			companyB + "/" + ownerSub: {isMember: true, active: true},
		},
		false,
	)
	mustExecAuthz(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
	mustExecAuthz(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true)`, fragMod, testDocsFragment)
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id = $1`, docB)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, docB)
	})
	// The document lives in company B: owner tuple + B's anchor (what docs' create writes).
	grantTestDocTuple(t, pool, "test_docs_document", docB, "editor", ownerSub)
	anchorTestDoc(t, pool, docB, companyB, moduleKey)

	can := func(t *testing.T, companyID string) (bool, string, []decision.Evidence) {
		t.Helper()
		body := mustJSON(t, map[string]any{
			"featureKey": "docs.document.access", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID,
			"object":    map[string]string{"type": "test_docs_document", "id": docB},
			"relation":  "editor",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, ownerSub, time.Now().Add(time.Hour)))
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

	t.Run("company B's own path: allowed", func(t *testing.T) {
		allowed, reason, ev := can(t, companyB)
		if !allowed || reason != "ALLOWED" {
			t.Fatalf("allowed=%v reason=%s ev=%+v, want ALLOWED", allowed, reason, ev)
		}
		if v, _ := evidenceValue(ev, "objectCompany"); v != "true" {
			t.Fatalf("objectCompany evidence = %q, want true", v)
		}
	})

	t.Run("company A's path to B's document: ENGINE_DENIED objectCompany=false", func(t *testing.T) {
		allowed, reason, ev := can(t, companyA)
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
