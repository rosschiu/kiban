// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedCompanyRoleFragment grants exactly the given company#<relation> tuples so TestHandleSummary
// can prove roleBindings picks up more than one company relation. "company" is a platform
// BASE type, always loaded (internal/authz/engine.BaseModel) with both #admin and #viewer
// resolvable via "this" (among other branches) with zero module fragments — so this installs
// no synthetic "company" model fragment (the base-type-redeclaration reject would refuse one).
// moduleKey is kept as a parameter for call-site compatibility; nothing here writes an
// authz.model_fragment row.
func seedCompanyRoleFragment(t *testing.T, pool *pgxpool.Pool, moduleKey, companyID string, grants map[string]string) {
	t.Helper()
	_ = moduleKey

	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_type = 'company' AND object_id = $1`, companyID)
	for subjectID, relation := range grants {
		mustExecAuthz(t, pool,
			`INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('company', $1, $2, 'user', $3)`,
			companyID, relation, subjectID)
	}
	t.Cleanup(func() {
		mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_type = 'company' AND object_id = $1`, companyID)
	})
}

func TestHandleSummary(t *testing.T) {
	const (
		moduleKey     = "http-summary-mod"
		companyID     = "http-summary-co"
		adminSub      = "http-summary-admin"
		viewerSub     = "http-summary-viewer"
		globalAdmin   = "http-summary-global-admin"
		unknownSub    = "http-summary-unknown"
		plainMemberID = "http-summary-plain-member"
	)

	svc, _, pool := buildHTTPService(t,
		map[string][]string{adminSub: nil, viewerSub: nil, globalAdmin: {"kiban-superadmin"}, plainMemberID: nil},
		map[string]bool{moduleKey: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyID + "/" + adminSub:      {isMember: true, active: true},
			companyID + "/" + viewerSub:     {isMember: true, active: true},
			companyID + "/" + plainMemberID: {isMember: true, active: true},
		},
		false,
	)
	seedCompanyRoleFragment(t, pool, moduleKey, companyID, map[string]string{adminSub: "admin", viewerSub: "viewer"})

	t.Run("missing kcSub: 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary", nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("no bearer required (internal, kcSub-as-param read)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+unknownSub, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (no Authorization header sent), body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown kcSub, no companyId: apiVersion/subjectId set, every array empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+unknownSub, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		data := body["data"]
		if data["apiVersion"] != float64(1) || data["subjectId"] != unknownSub || data["companyId"] != "" || data["moduleKey"] != "" {
			t.Fatalf("data = %+v, want apiVersion=1 subjectId=%s companyId=\"\" moduleKey=\"\"", data, unknownSub)
		}
		for _, field := range []string{"featureKeys", "roleBindings", "objectAccess", "rowScopes", "fieldPolicies"} {
			arr, ok := data[field].([]any)
			if !ok || len(arr) != 0 {
				t.Fatalf("data[%q] = %+v, want an empty array", field, data[field])
			}
		}
	})

	t.Run("global superadmin: featureKeys + roleBindings carry the superadmin entry", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+globalAdmin, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		data := body["data"]
		featureKeys := data["featureKeys"].([]any)
		if len(featureKeys) != 1 || featureKeys[0] != "auth.platform_administration.access" {
			t.Fatalf("featureKeys = %+v, want exactly [auth.platform_administration.access]", featureKeys)
		}
		roleBindings := data["roleBindings"].([]any)
		if len(roleBindings) != 1 {
			t.Fatalf("roleBindings = %+v, want exactly 1 entry", roleBindings)
		}
		rb := roleBindings[0].(map[string]any)
		if rb["scope"] != "global" || rb["role"] != "kiban-superadmin" {
			t.Fatalf("roleBindings[0] = %+v, want scope=global role=kiban-superadmin", rb)
		}
	})

	t.Run("company-scoped: enabled module's <moduleKey>.access feature key and the held company relation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+adminSub+"&companyId="+companyID, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		data := body["data"]
		if data["companyId"] != companyID {
			t.Fatalf("companyId = %v, want %s", data["companyId"], companyID)
		}
		featureKeys := data["featureKeys"].([]any)
		if len(featureKeys) != 1 || featureKeys[0] != moduleKey+".access" {
			t.Fatalf("featureKeys = %+v, want exactly [%s.access]", featureKeys, moduleKey)
		}
		// "company" is the platform BASE type (internal/authz/engine.BaseModel), whose real
		// #viewer relation is `union(this, computedUserset(admin))` — an admin holder is
		// CORRECTLY also a viewer (the base model's own semantics, not something this test
		// fabricates), so adminSub's direct company#admin grant surfaces BOTH roleBindings.
		roleBindings := data["roleBindings"].([]any)
		if len(roleBindings) != 2 {
			t.Fatalf("roleBindings = %+v, want exactly 2 entries (admin + implied viewer)", roleBindings)
		}
		gotRoles := map[string]bool{}
		for _, entry := range roleBindings {
			rb := entry.(map[string]any)
			if rb["scope"] != "company" || rb["companyId"] != companyID {
				t.Fatalf("roleBindings entry = %+v, want scope=company companyId=%s", rb, companyID)
			}
			gotRoles[rb["role"].(string)] = true
		}
		if !gotRoles["admin"] || !gotRoles["viewer"] {
			t.Fatalf("roleBindings roles = %+v, want {admin, viewer}", gotRoles)
		}
	})

	t.Run("company-scoped: a different member holds viewer, not admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+viewerSub+"&companyId="+companyID, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		roleBindings := body["data"]["roleBindings"].([]any)
		if len(roleBindings) != 1 {
			t.Fatalf("roleBindings = %+v, want exactly 1 entry", roleBindings)
		}
		rb := roleBindings[0].(map[string]any)
		if rb["role"] != "viewer" {
			t.Fatalf("roleBindings[0] = %+v, want role=viewer", rb)
		}
	})

	t.Run("company member with no company relation: featureKey still allowed, no roleBindings", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+plainMemberID+"&companyId="+companyID, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		data := body["data"]
		featureKeys := data["featureKeys"].([]any)
		if len(featureKeys) != 1 || featureKeys[0] != moduleKey+".access" {
			t.Fatalf("featureKeys = %+v, want exactly [%s.access] (module reachability doesn't need a company role)", featureKeys, moduleKey)
		}
		roleBindings := data["roleBindings"].([]any)
		if len(roleBindings) != 0 {
			t.Fatalf("roleBindings = %+v, want empty (plain member holds no company relation)", roleBindings)
		}
	})

	t.Run("objectAccess: direct tuples grouped by object, unrelated subjects excluded", func(t *testing.T) {
		const subject = "http-summary-objaccess"
		mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE subject_type = 'user' AND subject_id = $1`, subject)
		mustExecAuthz(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('member_directory', 'md1', 'viewer', 'user', $1)`, subject)
		mustExecAuthz(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('member_directory', 'md1', 'editor', 'user', $1)`, subject)
		mustExecAuthz(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('access_bundle', 'ab1', 'member', 'user', $1)`, subject)
		t.Cleanup(func() {
			mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE subject_type = 'user' AND subject_id = $1`, subject)
		})

		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+subject, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		objectAccess := body["data"]["objectAccess"].([]any)
		if len(objectAccess) != 2 {
			t.Fatalf("objectAccess = %+v, want 2 grouped objects", objectAccess)
		}
		first := objectAccess[0].(map[string]any)
		if first["objectType"] != "access_bundle" || first["objectId"] != "ab1" {
			t.Fatalf("objectAccess[0] = %+v, want access_bundle:ab1 (SQL-sorted before member_directory)", first)
		}
		second := objectAccess[1].(map[string]any)
		if second["objectType"] != "member_directory" || second["objectId"] != "md1" {
			t.Fatalf("objectAccess[1] = %+v, want member_directory:md1", second)
		}
		relations := second["relations"].([]any)
		if len(relations) != 2 || relations[0] != "editor" || relations[1] != "viewer" {
			t.Fatalf("objectAccess[1].relations = %+v, want [editor, viewer] (SQL-sorted)", relations)
		}
	})

	// buildHTTPService's fake identity server has no 5s timeout hazard for this test's sizes,
	// but the summary endpoint itself has no fixed timeout budget of its own — this asserts it
	// still returns promptly for a handful of modules.
	t.Run("responds well within a generous bound", func(t *testing.T) {
		start := time.Now()
		req := httptest.NewRequest(http.MethodGet, "/internal/authz/effective-access/summary?kcSub="+adminSub+"&companyId="+companyID, nil)
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("summary took %s, want well under 5s", elapsed)
		}
	})
}
