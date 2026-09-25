// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

// Covers platform_role.go end to end against the live authz store: grant, revoke, the
// last-superadmin 409 (self and other), the non-superadmin bearer 403, the unknown role 422,
// the unknown subject 404, and the audit + ledger rows each write leaves behind.
func TestPlatformRoleRoutes(t *testing.T) {
	const admin, second, plain, unknownInIdentity = "pr-admin", "pr-second", "pr-plain", "pr-nobody"
	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{admin: {"kiban-superadmin"}, second: nil, plain: nil},
		nil, nil, nil, false)
	ctx := context.Background()
	// The last-superadmin rule is platform-wide, and this shared test database already holds the
	// stack's real seeded superadmin (plus whatever other tests left): park every superadmin
	// tuple that is not this test's own for the test's duration and put it back afterwards
	// (registered first, so it runs last).
	rows, err := pool.Query(ctx, `DELETE FROM authz.tuple WHERE object_type='system' AND object_id='platform' AND relation='superadmin' AND subject_type='user' AND subject_id NOT IN ($1, $2, $3) RETURNING subject_id, subject_relation`, admin, second, plain)
	if err != nil {
		t.Fatalf("park other superadmin tuples: %v", err)
	}
	var parked [][2]string
	for rows.Next() {
		var sub, rel string
		if err := rows.Scan(&sub, &rel); err != nil {
			t.Fatalf("scan parked tuple: %v", err)
		}
		parked = append(parked, [2]string{sub, rel})
	}
	rows.Close()
	t.Cleanup(func() {
		for _, p := range parked {
			_, _ = pool.Exec(context.Background(), `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES ('system','platform','superadmin','user',$1,$2) ON CONFLICT DO NOTHING`, p[0], p[1])
		}
	})
	t.Cleanup(func() {
		for _, sub := range []string{admin, second, plain} {
			_, _ = pool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type = 'system' AND subject_id = $1`, sub)
			_, _ = pool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type = 'system' AND subject_id = $1`, sub)
		}
	})

	do := func(t *testing.T, method, path, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body != nil {
			req = httptest.NewRequest(method, path, mustJSON(t, body))
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, bearer, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}
	expect := func(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, status, rec.Body.String())
		}
		if code != "" {
			var body map[string]map[string]any
			decodeBody(t, rec, &body)
			if body["error"]["code"] != code {
				t.Fatalf("error code = %v, want %s (body=%s)", body["error"]["code"], code, rec.Body.String())
			}
		}
	}
	held := func(t *testing.T, sub string) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuple WHERE object_type='system' AND object_id='platform' AND relation='superadmin' AND subject_type='user' AND subject_id=$1`, sub).Scan(&n); err != nil {
			t.Fatalf("count tuple: %v", err)
		}
		return n == 1
	}
	auditRows := func(t *testing.T, action, sub string) int {
		t.Helper()
		var n int
		if err := adminPool(t).QueryRow(ctx, `SELECT count(*) FROM audit.authz__events WHERE action = $1 AND subject = $2 AND actor = $3 AND payload->>'role' = 'kiban-superadmin' AND payload->>'grantedBy' = $3`, action, "user:"+sub, admin).Scan(&n); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return n
	}
	ledgerRows := func(t *testing.T, op, sub string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.grant_ledger WHERE object_type='system' AND subject_id=$1 AND op=$2 AND actor=$3`, sub, op, admin).Scan(&n); err != nil {
			t.Fatalf("count ledger rows: %v", err)
		}
		return n
	}
	const grantPath = "/internal/authz/platform-roles"
	revokePath := func(role, sub string) string { return grantPath + "/" + role + "/" + sub }

	t.Run("unknown role is 422 on grant and revoke, before any authorization", func(t *testing.T) {
		expect(t, do(t, http.MethodPost, grantPath, admin, map[string]string{"subjectId": second, "role": "kiban-operator"}), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
		expect(t, do(t, http.MethodDelete, revokePath("kiban-operator", second), admin, nil), http.StatusUnprocessableEntity, errenv.CodeValidationFailed)
	})
	t.Run("empty subject and bad JSON are 400", func(t *testing.T) {
		expect(t, do(t, http.MethodPost, grantPath, admin, map[string]string{"role": "kiban-superadmin"}), http.StatusBadRequest, errenv.CodeBadRequest)
		req := httptest.NewRequest(http.MethodPost, grantPath, nil)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, admin, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		expect(t, rec, http.StatusBadRequest, errenv.CodeBadRequest)
	})
	t.Run("no bearer is 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, grantPath, mustJSON(t, map[string]string{"subjectId": second, "role": "kiban-superadmin"})))
		expect(t, rec, http.StatusUnauthorized, errenv.CodeAuthTokenMissing)
	})
	t.Run("a non-superadmin bearer is 403 and the denial is audited", func(t *testing.T) {
		expect(t, do(t, http.MethodPost, grantPath, plain, map[string]string{"subjectId": plain, "role": "kiban-superadmin"}), http.StatusForbidden, errenv.CodeAuthorizationDenied)
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", admin), plain, nil), http.StatusForbidden, errenv.CodeAuthorizationDenied)
		if held(t, plain) {
			t.Fatal("a denied grant must write nothing")
		}
		var n int
		if err := adminPool(t).QueryRow(ctx, `SELECT count(*) FROM audit.authz__events WHERE actor = $1 AND action = 'authz.effective_access.denied' AND subject IN ('authz.platform_role.grant', 'authz.platform_role.revoke')`, plain).Scan(&n); err != nil {
			t.Fatalf("count denial audit rows: %v", err)
		}
		if n < 2 {
			t.Fatalf("denial audit rows = %d, want >= 2", n)
		}
	})
	t.Run("a subject identity has never seen is 404", func(t *testing.T) {
		expect(t, do(t, http.MethodPost, grantPath, admin, map[string]string{"subjectId": unknownInIdentity, "role": "kiban-superadmin"}), http.StatusNotFound, errenv.CodeNotFound)
	})
	t.Run("revoking a subject that does not hold the role is 404", func(t *testing.T) {
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", second), admin, nil), http.StatusNotFound, errenv.CodeNotFound)
	})
	// audit.authz__events is append-only and shared across runs: every assertion below is a delta.
	t.Run("the last superadmin cannot revoke themselves: 409, tuple kept", func(t *testing.T) {
		before := auditRows(t, "authz.platform_role.revoke", admin)
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", admin), admin, nil), http.StatusConflict, errenv.CodeConflict)
		if !held(t, admin) {
			t.Fatal("the refused revoke must leave the tuple in place")
		}
		if n := auditRows(t, "authz.platform_role.revoke", admin) - before; n != 0 {
			t.Fatalf("refused revoke audit rows = %d, want 0", n)
		}
	})
	t.Run("grant writes the tuple, one ledger row and one audit row, and is effective immediately", func(t *testing.T) {
		before := auditRows(t, "authz.platform_role.grant", second)
		expect(t, do(t, http.MethodPost, grantPath, admin, map[string]string{"subjectId": second, "role": "kiban-superadmin"}), http.StatusOK, "")
		if !held(t, second) {
			t.Fatal("tuple not written")
		}
		if n := ledgerRows(t, "grant", second); n != 1 {
			t.Fatalf("ledger grant rows = %d, want 1", n)
		}
		if n := auditRows(t, "authz.platform_role.grant", second) - before; n != 1 {
			t.Fatalf("audit grant rows = %d, want 1", n)
		}
		rec := do(t, http.MethodPost, "/internal/authz/effective-access/can", second, map[string]any{
			"featureKey": "auth.platform_administration.access", "scope": "global", "requiredPlatformRole": "kiban-superadmin",
		})
		expect(t, rec, http.StatusOK, "")
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		if body["data"]["allowed"] != true {
			t.Fatalf("new superadmin's global decision = %+v, want allowed", body["data"])
		}
	})
	t.Run("with two superadmins either may be revoked; the new holder revokes the original", func(t *testing.T) {
		revokeAudits := func() int {
			var n int
			if err := adminPool(t).QueryRow(ctx, `SELECT count(*) FROM audit.authz__events WHERE action = 'authz.platform_role.revoke' AND subject = $1 AND actor = $2`, "user:"+admin, second).Scan(&n); err != nil {
				t.Fatalf("count revoke audit rows: %v", err)
			}
			return n
		}
		before := revokeAudits()
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", admin), second, nil), http.StatusOK, "")
		if held(t, admin) {
			t.Fatal("tuple not removed")
		}
		if n := revokeAudits() - before; n != 1 {
			t.Fatalf("revoke audit rows = %d, want 1", n)
		}
		rec := do(t, http.MethodPost, "/internal/authz/effective-access/can", admin, map[string]any{
			"featureKey": "auth.platform_administration.access", "scope": "global", "requiredPlatformRole": "kiban-superadmin",
		})
		expect(t, rec, http.StatusOK, "")
		var body map[string]map[string]any
		decodeBody(t, rec, &body)
		if body["data"]["allowed"] != false || body["data"]["reason"] != "PLATFORM_ROLE_REQUIRED" {
			t.Fatalf("revoked superadmin's global decision = %+v, want PLATFORM_ROLE_REQUIRED", body["data"])
		}
		// The original is now a plain user: revoking the remaining (last) superadmin is 403.
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", second), admin, nil), http.StatusForbidden, errenv.CodeAuthorizationDenied)
		// And the remaining one cannot remove themselves either.
		expect(t, do(t, http.MethodDelete, revokePath("kiban-superadmin", second), second, nil), http.StatusConflict, errenv.CodeConflict)
	})
	t.Run("engine unavailable: 503, nothing written", func(t *testing.T) {
		broken := *svc
		broken.KnownEnabled = func(context.Context) (map[string]bool, error) { return nil, errFixtureKnownEnabled }
		req := httptest.NewRequest(http.MethodPost, grantPath, mustJSON(t, map[string]string{"subjectId": plain, "role": "kiban-superadmin"}))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, second, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		broken.Routes().ServeHTTP(rec, req)
		expect(t, rec, http.StatusInternalServerError, errenv.CodeInternalError)
		if held(t, plain) {
			t.Fatal("nothing may be written when the decider cannot be built")
		}
	})
	t.Run("identity unreachable on the subject lookup: 503", func(t *testing.T) {
		unreachable := httptest.NewServer(http.NotFoundHandler())
		unreachable.Close()
		broken := *svc
		broken.Identity = NewIdentityClient(&http.Client{Timeout: 300 * time.Millisecond}, unreachable.URL)
		req := httptest.NewRequest(http.MethodPost, grantPath, mustJSON(t, map[string]string{"subjectId": plain, "role": "kiban-superadmin"}))
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, second, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		broken.Routes().ServeHTTP(rec, req)
		expect(t, rec, http.StatusServiceUnavailable, errenv.CodeAuthorizationUnavailable)
	})
	t.Run("store.CountSuperadmins counts direct holders only", func(t *testing.T) {
		n, err := store.CountSuperadmins(ctx, pool)
		if err != nil || n < 1 {
			t.Fatalf("CountSuperadmins = %d, %v; want >= 1", n, err)
		}
	})
}
