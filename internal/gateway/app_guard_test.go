// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSnapshot_AppForClient(t *testing.T) {
	snap := Snapshot{fetchedAt: time.Now(), byKey: map[string]ModuleEntry{
		"tokidesk":     {ModuleKey: "tokidesk", Installed: true, External: true, ServiceClientID: "tokidesk-backend"},
		"notification": {ModuleKey: "notification", Installed: true, Enabled: true, Port: 8150},
		"gone":         {ModuleKey: "gone", Installed: false, External: true, ServiceClientID: "gone-backend"},
	}}
	if e, ok := snap.AppForClient("tokidesk-backend"); !ok || e.ModuleKey != "tokidesk" {
		t.Fatalf("AppForClient(tokidesk-backend) = %+v %v", e, ok)
	}
	for _, id := range []string{"", "gone-backend", "kiban-identity-service"} {
		if _, ok := snap.AppForClient(id); ok {
			t.Errorf("AppForClient(%q) matched, want no app", id)
		}
	}
}

// An app's backend (azp = its service client id) passes the grants guard without a superadmin
// check; any other bearer takes the superadmin path, which with no admin client fails closed.
func TestRequireSuperadminOrApp(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{ModuleKey: "tokidesk", Installed: true, External: true, ServiceClientID: "tokidesk-backend"}}, nil)
	catalog := NewCatalogClient(reg.server.URL, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := RequireSuperadminOrApp(nil, catalog, "authz.grants.write")(next)

	call := func(authCtx AuthContext) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/grants", nil)
		req.Header.Set("Authorization", "Bearer x")
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req.WithContext(ContextWithAuth(req.Context(), authCtx)))
		return rec.Code
	}
	if got := call(AuthContext{Subject: "sa", ClientID: "tokidesk-backend"}); got != http.StatusNoContent {
		t.Errorf("app backend: status %d, want 204", got)
	}
	if got := call(AuthContext{Subject: "u", ClientID: "kiban-frontend"}); got != http.StatusServiceUnavailable {
		t.Errorf("browser client with no admin client: status %d, want 503 (fail closed)", got)
	}
	if got := call(AuthContext{Subject: "u"}); got != http.StatusServiceUnavailable {
		t.Errorf("no azp with no admin client: status %d, want 503 (fail closed)", got)
	}
}

func TestProxy_ExternalAppIs404(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{ModuleKey: "tokidesk", Installed: true, Enabled: true, External: true, ServiceClientID: "tokidesk-backend"}}, nil)
	gw := newTestProxyServer(t, reg.server.URL)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/api/tokidesk/tickets")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if code := decodeErrorCode(t, resp); code != "NOT_FOUND" {
		t.Errorf("code = %q, want NOT_FOUND", code)
	}
}
