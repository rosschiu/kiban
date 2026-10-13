// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
)

// The owner rule: the app that registered module M (its token's azp == M's service client id)
// writes tuples on M's own types without company membership; it still cannot touch another
// module's types, and a token for a different client gets the ordinary membership rule.
func TestHandleGrants_OwnerApp(t *testing.T) {
	const (
		mod, otherMod = "ho-mod", "ho-other"
		appSub        = "ho-app-sa" // the service-account user
		appClient     = "ho-app-backend"
	)
	companyID := uuid.NewString()
	fakeAppOwners = map[string]string{mod: appClient}
	t.Cleanup(func() { fakeAppOwners = map[string]string{} })

	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{appSub: nil},
		map[string]bool{mod: true, otherMod: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{}, // the app's service account is a member of nothing
		false,
	)
	frag := `{"ho_doc": {"company_module": {"this": true}, "viewer": {"this": true}}}`
	otherFrag := `{"ho_thing": {"company_module": {"this": true}, "viewer": {"this": true}}}`
	mustExecAuthz(t, pool, `DELETE FROM authz.model_fragment WHERE module_key IN ($1, $2)`, mod, otherMod)
	mustExecAuthz(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true), ($3, $4::jsonb, true)`, mod, frag, otherMod, otherFrag)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key IN ($1, $2)`, mod, otherMod)
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id LIKE 'ho-%' OR object_id LIKE $1`, companyID+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id LIKE 'ho-%' OR object_id LIKE $1`, companyID+"%")
	})

	expect := func(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
		}
		var env struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if env.Error.Code != code {
			t.Fatalf("code %q, want %q: %s", env.Error.Code, code, rec.Body.String())
		}
	}
	postOp := func(op, azp string, tuples []map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		body := map[string]any{"op": op, "companyId": companyID, "tuples": tuples}
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/grants", mustJSON(t, body))
		req.Header.Set("Authorization", "Bearer "+issuer.signClient(t, appSub, azp, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}
	post := func(azp string, tuples []map[string]string) *httptest.ResponseRecorder {
		return postOp("grant", azp, tuples)
	}
	anchor := func(typ, id, module string) map[string]string {
		return map[string]string{"objectType": typ, "objectId": id, "relation": "company_module", "subjectType": "company_module", "subjectId": companyID + "/" + module}
	}
	viewer := func(typ, id string) map[string]string {
		return map[string]string{"objectType": typ, "objectId": id, "relation": "viewer", "subjectType": "user", "subjectId": "ho-reader"}
	}

	t.Run("owning app writes its own types with no membership", func(t *testing.T) {
		rec := post(appClient, []map[string]string{anchor("ho_doc", "ho-d1", mod), viewer("ho_doc", "ho-d1")})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authz.tuple WHERE object_type = 'ho_doc' AND object_id = 'ho-d1' AND relation = 'viewer'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("viewer tuple not written: n=%d err=%v", n, err)
		}
	})

	t.Run("owning app revokes the rest after the anchor is gone, so nothing is stranded", func(t *testing.T) {
		expect(t, post(appClient, []map[string]string{anchor("ho_doc", "ho-d3", mod), viewer("ho_doc", "ho-d3")}), http.StatusOK, "")
		expect(t, postOp("revoke", appClient, []map[string]string{anchor("ho_doc", "ho-d3", mod)}), http.StatusOK, "")
		expect(t, postOp("revoke", appClient, []map[string]string{viewer("ho_doc", "ho-d3")}), http.StatusOK, "")
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authz.tuple WHERE object_type = 'ho_doc' AND object_id = 'ho-d3'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("tuples left on ho-d3 = %d, err=%v; want none", n, err)
		}
		// Anchoring the same id again revives nothing.
		expect(t, post(appClient, []map[string]string{anchor("ho_doc", "ho-d3", mod)}), http.StatusOK, "")
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authz.tuple WHERE object_type = 'ho_doc' AND object_id = 'ho-d3' AND relation = 'viewer'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("viewer on re-anchored ho-d3 = %d, err=%v; want none", n, err)
		}
	})

	t.Run("owning app cannot revoke from an object anchored to another company", func(t *testing.T) {
		otherCompany := uuid.NewString()
		mustExecAuthz(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('ho_doc', 'ho-d4', 'company_module', 'company_module', $1, ''), ('ho_doc', 'ho-d4', 'viewer', 'user', 'ho-reader', '')`, otherCompany+"/"+mod)
		expect(t, postOp("revoke", appClient, []map[string]string{viewer("ho_doc", "ho-d4")}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})

	t.Run("owning app cannot write another module's types", func(t *testing.T) {
		rec := post(appClient, []map[string]string{anchor("ho_thing", "ho-t1", otherMod), viewer("ho_thing", "ho-t1")})
		expect(t, rec, http.StatusForbidden, errenv.CodeAuthorizationDenied)
	})

	t.Run("a different client falls back to the membership rule", func(t *testing.T) {
		rec := post("someone-else", []map[string]string{anchor("ho_doc", "ho-d2", mod), viewer("ho_doc", "ho-d2")})
		expect(t, rec, http.StatusForbidden, errenv.CodeAuthorizationDenied)
	})
}
