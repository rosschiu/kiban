// SPDX-License-Identifier: Apache-2.0

//go:build live

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
	"github.com/rosschiu/kiban/sdk"
)

// The whole "app beside Kiban" story against the isolated test stack: a superadmin registers
// an app from its manifest and enables it, creates a company and links a user as its member;
// the app's backend (the Go SDK, authenticated as the app's service client) grants that user
// viewer on one of its objects; the user's own check is allowed, a feature the manifest does
// not declare is refused, and the app can look the member up. Nothing here touches the
// network inside Compose: every call goes through the gateway.
func TestLive_AppBesideKiban(t *testing.T) {
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}
	ctx := context.Background()
	spec := platformOpenAPISpec(t)
	gwBase := "https://127.0.0.1:" + platformLiveEnv(t, "KIBAN_GATEWAY_TLS_HOST_PORT")
	kcBase := "http://127.0.0.1:" + platformLiveEnv(t, "KEYCLOAK_HOST_PORT")
	realm := platformLiveEnv(t, "KEYCLOAK_REALM")
	adminBase := kcBase + "/admin/realms/" + realm
	plainHTTP := &http.Client{Timeout: 10 * time.Second}
	tlsClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	const appKey, clientID = "livestory", "livestory-backend"

	// --- Keycloak: the app's confidential service client (what KIBAN_SERVICE_CLIENTS does at
	// bootstrap), created through the admin API for this test only. ---
	kcAdmin := platformKCAdminToken(t, plainHTTP, kcBase)
	kcDo := func(method, path string, body any) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(ctx, method, adminBase+path, rdr)
		req.Header.Set("Authorization", "Bearer "+kcAdmin)
		req.Header.Set("Content-Type", "application/json")
		resp, err := plainHTTP.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, raw
	}
	if resp, raw := kcDo(http.MethodGet, "/clients?clientId="+clientID, nil); resp.StatusCode == 200 {
		var existing []struct{ ID string }
		_ = json.Unmarshal(raw, &existing)
		for _, e := range existing {
			kcDo(http.MethodDelete, "/clients/"+e.ID, nil)
		}
	}
	resp, raw := kcDo(http.MethodPost, "/clients", map[string]any{
		"clientId": clientID, "enabled": true, "protocol": "openid-connect", "publicClient": false,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		"protocolMappers": []map[string]any{{
			"name": "kiban-api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{"included.client.audience": "kiban-api", "access.token.claim": "true", "id.token.claim": "false"},
		}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create service client: HTTP %d: %s", resp.StatusCode, raw)
	}
	kcClientInternalID := resp.Header.Get("Location")[strings.LastIndex(resp.Header.Get("Location"), "/")+1:]
	t.Cleanup(func() { kcDo(http.MethodDelete, "/clients/"+kcClientInternalID, nil) })
	_, raw = kcDo(http.MethodGet, "/clients/"+kcClientInternalID+"/client-secret", nil)
	var secretRep struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(raw, &secretRep)

	// --- the superadmin and a plain user, logged in through the gateway. ---
	superadminID := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME"))
	superadminPassword := "story-" + platformRandString(t, 16)
	platformKCSetPassword(t, plainHTTP, adminBase, kcAdmin, superadminID, superadminPassword)
	adminBearer := platformInteractiveLogin(t, gwBase, realm, platformLiveEnv(t, "KIBAN_SUPERADMIN_USERNAME"), superadminPassword)
	const plainUsername = "kiban-story-user"
	plainPassword := "story-" + platformRandString(t, 16)
	platformKCEnsurePlainUser(t, plainHTTP, adminBase, kcAdmin, plainUsername, plainPassword)
	userBearer := platformInteractiveLogin(t, gwBase, realm, plainUsername, plainPassword)
	userSub := platformKCFindUser(t, plainHTTP, adminBase, kcAdmin, plainUsername)

	adminPool := platformLivePool(t, "kiban", platformLiveEnv(t, "KIBAN_DB_PASSWORD"))
	var companyID, companyBID string
	t.Cleanup(func() {
		if companyBID != "" {
			_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE $1 OR subject_id LIKE $1`, companyBID+"%")
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id = $1`, companyBID)
		}
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_type = 'livestory_ticket' OR object_id LIKE $1`, "%/"+appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.grant_ledger WHERE object_type = 'livestory_ticket' OR object_id LIKE $1`, "%/"+appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.default_grant WHERE module_key = $1`, appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM authz.model_fragment WHERE module_key = $1`, appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM platform.app_registration WHERE module_key = $1`, appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM platform.module_installation WHERE module_key = $1`, appKey)
		_, _ = adminPool.Exec(ctx, `DELETE FROM platform.module_catalog WHERE module_key = $1`, appKey)
		if companyID != "" {
			_, _ = adminPool.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id LIKE $1 OR subject_id LIKE $1`, companyID+"%")
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.group_member WHERE group_id IN (SELECT id FROM org.group WHERE company_id = $1)`, companyID)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.group WHERE company_id = $1`, companyID)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.position_assignment WHERE position_id IN (SELECT id FROM org.position WHERE company_id = $1)`, companyID)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.position WHERE company_id = $1`, companyID)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.member WHERE company_id = $1`, companyID)
			_, _ = adminPool.Exec(ctx, `DELETE FROM org.org_unit WHERE id = $1`, companyID)
		}
	})

	step := func(name, method, path, bearer string, body any, want int) map[string]any {
		t.Helper()
		var b []byte
		if body != nil {
			b = mustJSON(t, body)
		}
		req, rec := doPlatformRequest(t, tlsClient, method, gwBase+path, bearer, b)
		if rec.Code != want {
			t.Fatalf("%s: %s %s = HTTP %d, want %d: %s", name, method, path, rec.Code, want, rec.Body.String())
		}
		t.Run(name+"/spec", func(t *testing.T) { spec.ValidateResponse(t, req, rec) })
		var env struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		return env.Data
	}

	// --- 1. the superadmin registers and enables the app, creates the company and the member. ---
	step("registerApp", http.MethodPost, "/api/platform/admin/apps", adminBearer, map[string]any{
		"key": appKey, "displayName": "Live Story", "version": "1.0.0", "serviceClientId": clientID,
		"features":      []string{appKey + ".ticket.view"},
		"authzFragment": map[string]any{"livestory_ticket": map[string]any{"company_module": map[string]any{"this": true}, "viewer": map[string]any{"this": true}}},
	}, http.StatusOK)
	step("registerApp/422", http.MethodPost, "/api/platform/admin/apps", adminBearer, map[string]any{"key": "Bad Key"}, http.StatusUnprocessableEntity)
	step("enableApp", http.MethodPost, "/api/platform/admin/modules/"+appKey+"/enable", adminBearer, nil, http.StatusOK)
	company := step("createCompany", http.MethodPost, "/api/org/admin/units", adminBearer, map[string]any{
		"typeKey": "company", "parentId": nil, "code": "story" + platformRandString(t, 5), "name": "Story Co",
	}, http.StatusCreated)
	companyID, _ = company["id"].(string)
	member := step("createMember", http.MethodPost, "/api/org/admin/members", adminBearer, map[string]any{
		"companyId": companyID, "code": "storyuser", "displayName": "Story User", "email": "story@example.invalid",
	}, http.StatusCreated)
	// Identity provisions a subject on its first request through the gateway; link after that.
	step("userFirstRequest", http.MethodGet, "/api/org/me/companies", userBearer, nil, http.StatusOK)
	step("linkUser", http.MethodPost, "/api/org/admin/members/"+member["id"].(string)+"/link-user", adminBearer, map[string]any{"kcSub": userSub}, http.StatusOK)
	step("listMembers", http.MethodGet, "/api/org/admin/members?companyId="+companyID, adminBearer, nil, http.StatusOK)

	// --- 2. the app's backend, through the Go SDK. ---
	app, err := sdk.New(ctx, sdk.Config{GatewayURL: gwBase, ClientID: clientID, ClientSecret: secretRep.Value, HTTPClient: tlsClient})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	if sub, err := app.VerifyUserToken(ctx, userBearer); err != nil || sub != userSub {
		t.Fatalf("VerifyUserToken = %q, %v (want %q)", sub, err, userSub)
	}
	if err := app.Grant(ctx, companyID,
		sdk.AnchorTuple(appKey, "livestory_ticket", "t-1", companyID),
		sdk.Tuple{ObjectType: "livestory_ticket", ObjectID: "t-1", Relation: "viewer", SubjectType: "user", SubjectID: userSub},
	); err != nil {
		t.Fatalf("Grant as the app: %v", err)
	}
	// An object carries one anchor. A second company cannot claim t-1, even from the
	// owning app, and the first company's view of it is unchanged.
	companyB := step("createCompanyB", http.MethodPost, "/api/org/admin/units", adminBearer, map[string]any{
		"typeKey": "company", "parentId": nil, "code": "storyb" + platformRandString(t, 5), "name": "Story Co B",
	}, http.StatusCreated)
	companyBID, _ = companyB["id"].(string)
	err = app.Grant(ctx, companyBID,
		sdk.AnchorTuple(appKey, "livestory_ticket", "t-1", companyBID),
		sdk.Tuple{ObjectType: "livestory_ticket", ObjectID: "t-1", Relation: "viewer", SubjectType: "user", SubjectID: userSub},
	)
	var anchorErr *sdk.APIError
	if !asAPIError(err, &anchorErr) || anchorErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("second anchor from another company: err = %v, want 422", err)
	}
	fact, err := app.MemberBySubject(ctx, companyID, userSub)
	if err != nil || !fact.IsMember || !fact.IsActive {
		t.Fatalf("MemberBySubject = %+v, %v", fact, err)
	}

	// --- 3. the user's own check, the app's feature rule, and a stranger's denial. ---
	obj := &struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}{Type: "livestory_ticket", ID: "t-1"}
	d, err := app.Can(ctx, userBearer, sdk.CanRequest{FeatureKey: appKey + ".ticket.view", ModuleKey: appKey, CompanyID: companyID, Object: obj, Relation: "viewer"})
	if err != nil || !d.Allowed {
		t.Fatalf("user's check = %+v, %v; want allowed", d, err)
	}
	_, err = app.Can(ctx, userBearer, sdk.CanRequest{FeatureKey: appKey + ".ticket.delete", ModuleKey: appKey, CompanyID: companyID})
	var apiErr *sdk.APIError
	if !asAPIError(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("undeclared feature: err = %v, want 422", err)
	}
	d, err = app.Can(ctx, adminBearer, sdk.CanRequest{FeatureKey: appKey + ".ticket.view", ModuleKey: appKey, CompanyID: companyID, Object: obj, Relation: "viewer"})
	if err != nil || d.Allowed {
		t.Fatalf("a non-member's object check = %+v, %v; want denied", d, err)
	}

	// --- 4. the app cannot write outside its own types: another module's type falls to the
	// membership rule (the service account is a member of nothing), a base type is refused
	// outright. ---
	err = app.Grant(ctx, companyID, sdk.Tuple{ObjectType: "notification_channel", ObjectID: "story-ch", Relation: "company_module", SubjectType: "company_module", SubjectID: companyID + "/notification"})
	if !asAPIError(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("grant on another module's type: err = %v, want 403", err)
	}
	err = app.Grant(ctx, companyID, sdk.Tuple{ObjectType: "company", ObjectID: companyID, Relation: "member", SubjectType: "user", SubjectID: userSub})
	if !asAPIError(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("grant on a base type: err = %v, want 422", err)
	}
	// The one base-model tuple the route knows, company#admin, is a superadmin's appointment:
	// an app is refused, not told the type is unknown.
	err = app.Grant(ctx, companyID, sdk.Tuple{ObjectType: "company", ObjectID: companyID, Relation: "admin", SubjectType: "user", SubjectID: userSub})
	if !asAPIError(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("app appointing a company administrator: err = %v, want 403", err)
	}
	if err := app.Revoke(ctx, companyID, sdk.Tuple{ObjectType: "livestory_ticket", ObjectID: "t-1", Relation: "viewer", SubjectType: "user", SubjectID: userSub}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if d, _ := app.Can(ctx, userBearer, sdk.CanRequest{FeatureKey: appKey + ".ticket.view", ModuleKey: appKey, CompanyID: companyID, Object: obj, Relation: "viewer"}); d.Allowed {
		t.Fatal("after revoke the user's object check must be denied")
	}

	// --- 5. the service account is a user: a background job's own check is refused until an
	// administrator makes the service account a member of the company, and the directory then
	// shows it as kind "service". ---
	svcCheck := sdk.CanRequest{FeatureKey: appKey + ".ticket.view", ModuleKey: appKey, CompanyID: companyID}
	if d, err := app.CanService(ctx, svcCheck); err != nil || d.Allowed || d.Reason != "COMPANY_MEMBERSHIP_REQUIRED" {
		t.Fatalf("service check before membership = %+v, %v; want denied COMPANY_MEMBERSHIP_REQUIRED", d, err)
	}
	serviceToken, err := app.ServiceToken(ctx)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	serviceSub, err := app.VerifyUserToken(ctx, serviceToken)
	if err != nil {
		t.Fatalf("service token sub: %v", err)
	}
	svcMember := step("createServiceMember", http.MethodPost, "/api/org/admin/members", adminBearer, map[string]any{
		"companyId": companyID, "code": "LIVESTORY_SVC", "displayName": "Live Story (worker)",
	}, http.StatusCreated)
	step("linkServiceAccount", http.MethodPost, "/api/org/admin/members/"+svcMember["id"].(string)+"/link-user", adminBearer, map[string]any{"kcSub": serviceSub}, http.StatusOK)
	if d, err := app.CanService(ctx, svcCheck); err != nil || !d.Allowed {
		t.Fatalf("service check after membership = %+v, %v; want allowed", d, err)
	}
	dir := step("directoryShowsKind", http.MethodGet, "/api/org/companies/"+companyID+"/members", userBearer, nil, http.StatusOK)
	kinds := map[string]string{}
	if items, _ := dir["items"].([]any); items != nil {
		for _, it := range items {
			m, _ := it.(map[string]any)
			kinds[m["displayName"].(string)], _ = m["kind"].(string)
		}
	}
	if kinds["Live Story (worker)"] != "service" || kinds[member["displayName"].(string)] != "person" {
		t.Fatalf("directory kinds = %v; want the service account as service and the person as person", kinds)
	}

	// --- 6. the org reads through the SDK, as the app (a member now) and as the user. ---
	if page, err := app.MemberDirectory(ctx, companyID, "", 1, 25); err != nil || page.Total != 2 {
		t.Fatalf("MemberDirectory as the app = %+v, %v; want both members", page, err)
	}
	if cos, err := app.MeCompanies(ctx, userBearer); err != nil || len(cos) != 1 || cos[0].ID != companyID {
		t.Fatalf("MeCompanies for the user = %+v, %v; want the story company", cos, err)
	}
	position := step("createPosition", http.MethodPost, "/api/org/admin/companies/"+companyID+"/positions", adminBearer, map[string]any{"code": "CFO", "title": "CFO"}, http.StatusCreated)
	step("assign", http.MethodPost, "/api/org/admin/positions/"+position["id"].(string)+"/assignments", adminBearer, map[string]any{"memberId": member["id"].(string)}, http.StatusCreated)
	if holder, err := app.PositionHolder(ctx, companyID, position["id"].(string), time.Now()); err != nil || holder.MemberID != member["id"].(string) {
		t.Fatalf("PositionHolder = %+v, %v; want the story member", holder, err)
	}
	if _, err := app.PositionHolder(ctx, companyID, position["id"].(string), time.Now().AddDate(-1, 0, 0)); !asAPIError(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("PositionHolder a year ago: err = %v, want 404", err)
	}
	group := step("createGroup", http.MethodPost, "/api/org/admin/companies/"+companyID+"/groups", adminBearer, map[string]any{"code": "SUPPORT", "name": "Support"}, http.StatusCreated)
	step("addGroupMember", http.MethodPost, "/api/org/admin/groups/"+group["id"].(string)+"/members", adminBearer, map[string]any{"memberId": member["id"].(string)}, http.StatusCreated)
	if members, err := app.GroupMembers(ctx, companyID, group["id"].(string)); err != nil || len(members) != 1 || members[0].MemberID != member["id"].(string) {
		t.Fatalf("GroupMembers = %+v, %v; want the story member", members, err)
	}
	if results, err := app.BatchCan(ctx, userBearer, sdk.CanRequest{FeatureKey: appKey + ".ticket.view", ModuleKey: appKey, CompanyID: companyID}, []sdk.BatchItem{sdk.NewBatchItem("livestory_ticket", "t-1", "viewer")}); err != nil || len(results) != 1 || results[0].Decision.Allowed {
		t.Fatalf("BatchCan after revoke = %+v, %v; want one denied item", results, err)
	}

}

func asAPIError(err error, target **sdk.APIError) bool {
	e, ok := err.(*sdk.APIError)
	if ok {
		*target = e
	}
	return ok
}
