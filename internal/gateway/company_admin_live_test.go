// SPDX-License-Identifier: Apache-2.0

//go:build live

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestLive_CompanyAdministrator: a member holding a company's admin relation manages that
// company's members, positions, assignments and groups through the public admin routes, is
// refused on another company and on company creation, and the superadmin keeps working
// Real gateway, org and authz.
func TestLive_CompanyAdministrator(t *testing.T) {
	ctx := context.Background()
	realm := platformLiveEnv(t, "KEYCLOAK_REALM")
	gwBase := "https://127.0.0.1:" + platformLiveEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	kcBase := "http://127.0.0.1:" + platformLiveEnv(t, "KEYCLOAK_HOST_PORT")
	adminBase := kcBase + "/admin/realms/" + realm
	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	tlsClient := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	kcAdmin := platformKCAdminToken(t, plainHTTP, kcBase)

	superadmin := platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME")
	superadminID := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, superadmin)
	superadminPassword := "cadm-live-" + platformRandString(t, 16)
	platformKCSetPassword(t, plainHTTP, adminBase, kcAdmin, superadminID, superadminPassword)
	adminBearer := platformInteractiveLogin(t, gwBase, realm, superadmin, superadminPassword)

	carolUsername := "cadm-carol-" + strings.ToLower(platformRandString(t, 8))
	carolPassword := "cadm-carol-" + platformRandString(t, 16)
	platformKCEnsurePlainUser(t, plainHTTP, adminBase, kcAdmin, carolUsername, carolPassword)
	carolBearer := platformInteractiveLogin(t, gwBase, realm, carolUsername, carolPassword)
	carolSub := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, carolUsername)

	call := func(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			rd = strings.NewReader(string(mustJSON(t, body)))
		}
		req, err := http.NewRequestWithContext(ctx, method, gwBase+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := tlsClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var env map[string]any
		_ = json.Unmarshal(raw, &env)
		return resp.StatusCode, env
	}
	data := func(env map[string]any) map[string]any { d, _ := env["data"].(map[string]any); return d }
	id := func(env map[string]any) string { s, _ := data(env)["id"].(string); return s }

	// The superadmin sets the stage: two companies, Carol a member of the first.
	suffix := strings.ToUpper(platformRandString(t, 6))
	st, env := call(t, http.MethodPost, "/api/org/admin/units", adminBearer, map[string]any{"typeKey": "company", "parentId": nil, "code": "CADM" + suffix, "name": "Carol's company"})
	if st != http.StatusCreated {
		t.Fatalf("create company: %d %v", st, env)
	}
	mine := id(env)
	st, env = call(t, http.MethodPost, "/api/org/admin/units", adminBearer, map[string]any{"typeKey": "company", "parentId": nil, "code": "OTHR" + suffix, "name": "Other company"})
	if st != http.StatusCreated {
		t.Fatalf("create other company: %d %v", st, env)
	}
	other := id(env)
	adminPool := platformLivePool(t, "kiban", platformLiveEnv(t, "KIBAN_DB_PASSWORD"))
	t.Cleanup(func() {
		for _, co := range []string{mine, other} {
			_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE $1 OR subject_id LIKE $1`, co+"%")
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.group_member WHERE group_id IN (SELECT id FROM org.group WHERE company_id = $1)`, co)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.group WHERE company_id = $1`, co)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.position_assignment WHERE position_id IN (SELECT id FROM org.position WHERE company_id = $1)`, co)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.position WHERE company_id = $1`, co)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.member WHERE company_id = $1`, co)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id = $1`, co)
		}
	})
	st, env = call(t, http.MethodPost, "/api/org/admin/members", adminBearer, map[string]any{"companyId": mine, "code": "CAROL", "displayName": "Carol"})
	if st != http.StatusCreated {
		t.Fatalf("create Carol's member: %d %v", st, env)
	}
	carolMember := id(env)
	// Identity provisions a subject on its first request through the gateway; link after that.
	if st, _ = call(t, http.MethodGet, "/api/org/me/companies", carolBearer, nil); st != http.StatusOK {
		t.Fatalf("Carol's first request: %d", st)
	}
	if st, env = call(t, http.MethodPost, "/api/org/admin/members/"+carolMember+"/link-user", adminBearer, map[string]any{"kcSub": carolSub}); st != http.StatusOK {
		t.Fatalf("link Carol: %d %v", st, env)
	}
	// Before the admin relation: a plain member is refused.
	if st, _ = call(t, http.MethodPost, "/api/org/admin/members", carolBearer, map[string]any{"companyId": mine, "code": "EARLY", "displayName": "Too early"}); st != http.StatusForbidden {
		t.Fatalf("plain member creating a member = %d, want 403", st)
	}
	// The superadmin appoints Carol: the one base-model tuple the grants route accepts, and only
	// from a superadmin.
	if st, env = call(t, http.MethodPost, "/api/auth/grants", adminBearer, map[string]any{"op": "grant", "companyId": mine, "tuples": []map[string]string{
		{"objectType": "company", "objectId": mine, "relation": "admin", "subjectType": "user", "subjectId": carolSub},
	}}); st != http.StatusOK {
		t.Fatalf("grant company admin: %d %v", st, env)
	}

	// Carol manages her company.
	st, env = call(t, http.MethodPost, "/api/org/admin/members", carolBearer, map[string]any{"companyId": mine, "code": "DAVE", "displayName": "Dave"})
	if st != http.StatusCreated {
		t.Fatalf("Carol creates a member: %d %v", st, env)
	}
	dave := id(env)
	if st, _ = call(t, http.MethodPut, "/api/org/admin/members/"+dave, carolBearer, map[string]any{"displayName": "Dave B"}); st != http.StatusOK {
		t.Fatalf("Carol updates a member: %d", st)
	}
	if st, _ = call(t, http.MethodGet, "/api/org/admin/members?companyId="+mine, carolBearer, nil); st != http.StatusOK {
		t.Fatalf("Carol lists members: %d", st)
	}
	st, env = call(t, http.MethodPost, "/api/org/admin/companies/"+mine+"/positions", carolBearer, map[string]any{"code": "CFO", "title": "CFO"})
	if st != http.StatusCreated {
		t.Fatalf("Carol creates a position: %d %v", st, env)
	}
	position := id(env)
	st, env = call(t, http.MethodPost, "/api/org/admin/positions/"+position+"/assignments", carolBearer, map[string]any{"memberId": dave})
	if st != http.StatusCreated {
		t.Fatalf("Carol assigns: %d %v", st, env)
	}
	assignment := id(env)
	if st, _ = call(t, http.MethodGet, "/api/org/admin/companies/"+mine+"/positions", carolBearer, nil); st != http.StatusOK {
		t.Fatalf("Carol lists positions: %d", st)
	}
	if st, env = call(t, http.MethodPost, "/api/org/admin/assignments/"+assignment+"/end", carolBearer, nil); st != http.StatusOK {
		t.Fatalf("Carol ends an assignment: %d %v", st, env)
	}
	st, env = call(t, http.MethodPost, "/api/org/admin/companies/"+mine+"/groups", carolBearer, map[string]any{"code": "SUPPORT", "name": "Support"})
	if st != http.StatusCreated {
		t.Fatalf("Carol creates a group: %d %v", st, env)
	}
	group := id(env)
	if st, env = call(t, http.MethodPost, "/api/org/admin/groups/"+group+"/members", carolBearer, map[string]any{"memberId": dave}); st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("Carol adds a group member: %d %v", st, env)
	}
	if st, _ = call(t, http.MethodGet, "/api/org/admin/groups/"+group+"/members", carolBearer, nil); st != http.StatusOK {
		t.Fatalf("Carol lists group members: %d", st)
	}
	if st, _ = call(t, http.MethodDelete, "/api/org/admin/groups/"+group+"/members/"+dave, carolBearer, nil); st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("Carol removes a group member: %d", st)
	}

	// Not hers: another company, companies themselves, org units.
	for _, c := range []struct {
		name, method, path string
		body               any
	}{
		{"member in other company", http.MethodPost, "/api/org/admin/members", map[string]any{"companyId": other, "code": "X", "displayName": "X"}},
		{"list other company's members", http.MethodGet, "/api/org/admin/members?companyId=" + other, nil},
		{"position in other company", http.MethodPost, "/api/org/admin/companies/" + other + "/positions", map[string]any{"code": "CFO", "title": "CFO"}},
		{"groups of other company", http.MethodGet, "/api/org/admin/companies/" + other + "/groups", nil},
		{"create a company", http.MethodPost, "/api/org/admin/units", map[string]any{"typeKey": "company", "parentId": nil, "code": "NOPE" + suffix, "name": "Nope"}},
		{"read her own company unit", http.MethodGet, "/api/org/admin/units/" + mine, nil},
	} {
		if st, env := call(t, c.method, c.path, carolBearer, c.body); st != http.StatusForbidden {
			t.Errorf("%s = %d %v, want 403", c.name, st, env)
		}
	}
	if st, _ := call(t, http.MethodPut, "/api/org/admin/members/00000000-0000-0000-0000-000000000000", carolBearer, map[string]any{"displayName": "x"}); st != http.StatusNotFound {
		t.Errorf("unknown member = %d, want 404", st)
	}

	// The superadmin still manages everything.
	if st, env := call(t, http.MethodPost, "/api/org/admin/members", adminBearer, map[string]any{"companyId": other, "code": "ERIN", "displayName": "Erin"}); st != http.StatusCreated {
		t.Errorf("superadmin creates in the other company = %d %v", st, env)
	}
}
