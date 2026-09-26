// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Non-live unit tests for RealmStep's reconciliation helpers (internal/bootstrap/realm.go)
// against a fake Keycloak admin API. The idempotent create-if-missing/update-if-different
// bodies short-circuit on a long-lived, already-converged dev stack, so the create/rename/error
// branches below are only reachable this way, not via the live tests in
// realm_test.go/browser_login_live_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeKCFor is newFakeKC (kcmaster_test.go) with a caller-supplied realm alias, since some
// realm.go helpers only need the token + one path, same pattern reused across this file.
func fakeKCFor(t *testing.T, realm string, handler http.HandlerFunc) *kcMasterClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-token"})
	})
	mux.HandleFunc("/", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newKCMasterClient(srv.Client(), srv.URL, realm, "admin", "admin")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- reconcileRealmSettings ---

func TestReconcileRealmSettings(t *testing.T) {
	t.Run("every target setting already matches: no patch, no update call", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, realmTargetSettings)
			case http.MethodPut:
				t.Fatal("updateRealm should not be called when nothing differs")
			}
		})
		changed, err := reconcileRealmSettings(context.Background(), kc)
		if err != nil {
			t.Fatalf("reconcileRealmSettings: %v", err)
		}
		if changed {
			t.Error("changed = true, want false")
		}
	})

	t.Run("a differing setting triggers a patch containing only the diffs", func(t *testing.T) {
		var gotPatch map[string]any
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				current := map[string]any{}
				for k, v := range realmTargetSettings {
					current[k] = v
				}
				current["displayName"] = "Wrong Name"
				writeJSON(w, current)
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&gotPatch)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, err := reconcileRealmSettings(context.Background(), kc)
		if err != nil {
			t.Fatalf("reconcileRealmSettings: %v", err)
		}
		if !changed {
			t.Fatal("changed = false, want true")
		}
		if len(gotPatch) != 1 || gotPatch["displayName"] != "Kiban" {
			t.Errorf("patch = %v, want exactly {displayName: Kiban}", gotPatch)
		}
	})

	t.Run("brute-force and password-policy keys missing (pre-hardening realm): patched with exactly them", func(t *testing.T) {
		hardening := []string{"bruteForceProtected", "permanentLockout", "failureFactor", "waitIncrementSeconds",
			"maxFailureWaitSeconds", "maxDeltaTimeSeconds", "quickLoginCheckMilliSeconds", "minimumQuickLoginWaitSeconds", "passwordPolicy"}
		var gotPatch map[string]any
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				current := map[string]any{}
				for k, v := range realmTargetSettings {
					current[k] = v
				}
				for _, k := range hardening {
					delete(current, k)
				}
				current["bruteForceProtected"] = false // Keycloak's own default, not absent
				current["passwordPolicy"] = nil
				writeJSON(w, current)
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&gotPatch)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, err := reconcileRealmSettings(context.Background(), kc)
		if err != nil {
			t.Fatalf("reconcileRealmSettings: %v", err)
		}
		if !changed {
			t.Fatal("changed = false, want true")
		}
		if len(gotPatch) != len(hardening) {
			t.Errorf("patch = %v, want exactly the %d hardening keys", gotPatch, len(hardening))
		}
		for _, k := range hardening {
			if !equalRealmValue(gotPatch[k], realmTargetSettings[k]) {
				t.Errorf("patch[%s] = %v, want %v", k, gotPatch[k], realmTargetSettings[k])
			}
		}
		if gotPatch["passwordPolicy"] != "length(12) and notUsername and notEmail" || gotPatch["bruteForceProtected"] != true {
			t.Errorf("patch = %v, want passwordPolicy + bruteForceProtected pinned", gotPatch)
		}
	})

	t.Run("getRealm error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := reconcileRealmSettings(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("updateRealm error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, map[string]any{})
			case http.MethodPut:
				w.WriteHeader(http.StatusForbidden)
			}
		})
		if _, err := reconcileRealmSettings(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestEqualRealmValue_UnknownType(t *testing.T) {
	if equalRealmValue("x", []string{"a"}) {
		t.Error("equalRealmValue with an unsupported target kind should be false")
	}
}

// --- reconcileBearerOnlyClient ---

func TestReconcileBearerOnlyClient(t *testing.T) {
	t.Run("wanted client exists and already correct: converged", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{{ID: "id1", ClientID: "kiban-api", BearerOnly: true, Enabled: true}})
		})
		changed, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API")
		if err != nil {
			t.Fatalf("reconcileBearerOnlyClient: %v", err)
		}
		if changed {
			t.Error("changed = true, want false")
		}
	})

	t.Run("wanted client exists but needs repair", func(t *testing.T) {
		var updated kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Query().Get("clientId") == "kiban-api":
				writeJSON(w, []kcClientRep{{ID: "id1", ClientID: "kiban-api", BearerOnly: false, Enabled: false}})
			case r.Method == http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&updated)
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
			}
		})
		changed, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API")
		if err != nil {
			t.Fatalf("reconcileBearerOnlyClient: %v", err)
		}
		if !changed || !updated.BearerOnly || !updated.Enabled {
			t.Errorf("changed=%v updated=%+v, want repaired to bearer-only+enabled", changed, updated)
		}
	})

	t.Run("wanted client missing: created fresh", func(t *testing.T) {
		var created kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet:
				writeJSON(w, []kcClientRep{})
			case r.Method == http.MethodPost:
				_ = json.NewDecoder(r.Body).Decode(&created)
				w.Header().Set("Location", "http://kc/admin/realms/kiban/clients/new-id")
				w.WriteHeader(http.StatusCreated)
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
			}
		})
		changed, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API")
		if err != nil {
			t.Fatalf("reconcileBearerOnlyClient: %v", err)
		}
		if !changed || created.ClientID != "kiban-api" || !created.BearerOnly {
			t.Errorf("changed=%v created=%+v, want a fresh bearer-only kiban-api client", changed, created)
		}
	})

	t.Run("wanted-lookup error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("create error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{})
			case http.MethodPost:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("already-found repair PUT error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{{ID: "id1", ClientID: "kiban-api", BearerOnly: false}})
			case http.MethodPut:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := reconcileBearerOnlyClient(context.Background(), kc, "kiban-api", "Kiban API"); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// --- frontendOrigins (pure) ---

func TestFrontendOrigins(t *testing.T) {
	t.Run("empty domain: dev loopback origins", func(t *testing.T) {
		redirects, origins := frontendOrigins("")
		if len(redirects) != 5 || len(origins) != 5 {
			t.Fatalf("redirects=%v origins=%v, want 5 dev loopback entries each", redirects, origins)
		}
	})

	// web/shell is served BY the gateway at its own TLS origin (https://127.0.0.1:8443,
	// infra/compose.yaml's KIBAN_STATIC_DIR) — a real browser login
	// completes its OIDC redirect back to that origin, so it must be an allowed redirect
	// URI/web origin for kiban-frontend, same as the Vite dev-server origins already are.
	t.Run("empty domain: includes the gateway's own dev TLS origin", func(t *testing.T) {
		redirects, origins := frontendOrigins("")
		found := false
		for _, r := range redirects {
			if r == "https://127.0.0.1:8443/*" {
				found = true
			}
		}
		if !found {
			t.Errorf("redirects = %v, want it to include https://127.0.0.1:8443/*", redirects)
		}
		found = false
		for _, o := range origins {
			if o == "https://127.0.0.1:8443" {
				found = true
			}
		}
		if !found {
			t.Errorf("origins = %v, want it to include https://127.0.0.1:8443", origins)
		}
	})

	// Same reasoning, one port over — the isolated kiban-test stack's gateway TLS origin
	// (fixed port 18543) must also be an allowed redirect URI/web origin,
	// or web/shell/e2e's Playwright suite can never complete a real browser login against it.
	t.Run("empty domain: includes the isolated kiban-test stack's gateway TLS origin", func(t *testing.T) {
		redirects, origins := frontendOrigins("")
		found := false
		for _, r := range redirects {
			if r == "https://127.0.0.1:18543/*" {
				found = true
			}
		}
		if !found {
			t.Errorf("redirects = %v, want it to include https://127.0.0.1:18543/*", redirects)
		}
		found = false
		for _, o := range origins {
			if o == "https://127.0.0.1:18543" {
				found = true
			}
		}
		if !found {
			t.Errorf("origins = %v, want it to include https://127.0.0.1:18543", origins)
		}
	})

	t.Run("domain set: single https origin", func(t *testing.T) {
		redirects, origins := frontendOrigins("kiban.example")
		if len(redirects) != 1 || redirects[0] != "https://kiban.example/*" {
			t.Errorf("redirects = %v, want [https://kiban.example/*]", redirects)
		}
		if len(origins) != 1 || origins[0] != "https://kiban.example" {
			t.Errorf("origins = %v, want [https://kiban.example]", origins)
		}
	})
}

// --- reconcileFrontendClient ---

func TestReconcileFrontendClient(t *testing.T) {
	t.Run("already correct: converged", func(t *testing.T) {
		redirects, origins := frontendOrigins("")
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{{
				ID: "fe-id", ClientID: frontendClientID, RedirectUris: redirects, WebOrigins: origins,
				PublicClient: true, StandardFlowEnabled: true,
				Attributes: map[string]string{postLogoutRedirectURIsAttrKey: postLogoutRedirectURIsAttrValue},
			}})
		})
		changed, id, err := reconcileFrontendClient(context.Background(), kc, "")
		if err != nil {
			t.Fatalf("reconcileFrontendClient: %v", err)
		}
		if changed || id != "fe-id" {
			t.Errorf("changed=%v id=%q, want converged fe-id", changed, id)
		}
	})

	t.Run("needs repair (wrong origins, not public)", func(t *testing.T) {
		var updated kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{{ID: "fe-id", ClientID: frontendClientID, RedirectUris: []string{"http://wrong/*"}}})
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&updated)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, id, err := reconcileFrontendClient(context.Background(), kc, "")
		if err != nil {
			t.Fatalf("reconcileFrontendClient: %v", err)
		}
		if !changed || id != "fe-id" || !updated.PublicClient || !updated.StandardFlowEnabled {
			t.Errorf("changed=%v id=%q updated=%+v, want repaired", changed, id, updated)
		}
	})

	// A client found with everything else correct but missing (or wrong) KC 26's separate
	// post.logout.redirect.uris attribute must still be repaired — the SDK's logout-redirect
	// default depends on it: without it, KC shows an "invalid redirect uri" error page on
	// logout instead of completing it.
	t.Run("existing client missing post-logout-redirect-uris attribute: repaired", func(t *testing.T) {
		redirects, origins := frontendOrigins("")
		var updated kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{{
					ID: "fe-id", ClientID: frontendClientID, RedirectUris: redirects, WebOrigins: origins,
					PublicClient: true, StandardFlowEnabled: true,
					// No Attributes at all — the shape of a client created before this attribute existed.
				}})
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&updated)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, id, err := reconcileFrontendClient(context.Background(), kc, "")
		if err != nil {
			t.Fatalf("reconcileFrontendClient: %v", err)
		}
		if !changed || id != "fe-id" {
			t.Errorf("changed=%v id=%q, want repaired fe-id", changed, id)
		}
		if got := updated.Attributes[postLogoutRedirectURIsAttrKey]; got != postLogoutRedirectURIsAttrValue {
			t.Errorf("updated.Attributes[%q] = %q, want %q", postLogoutRedirectURIsAttrKey, got, postLogoutRedirectURIsAttrValue)
		}
	})

	t.Run("missing: created fresh", func(t *testing.T) {
		var created kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{})
			case http.MethodPost:
				_ = json.NewDecoder(r.Body).Decode(&created)
				w.Header().Set("Location", "http://kc/admin/realms/kiban/clients/fresh-fe-id")
				w.WriteHeader(http.StatusCreated)
			}
		})
		changed, id, err := reconcileFrontendClient(context.Background(), kc, "")
		if err != nil {
			t.Fatalf("reconcileFrontendClient: %v", err)
		}
		if !changed || id != "fresh-fe-id" || created.ClientID != frontendClientID || !created.PublicClient {
			t.Errorf("changed=%v id=%q created=%+v, want a fresh public client", changed, id, created)
		}
		if got := created.Attributes[postLogoutRedirectURIsAttrKey]; got != postLogoutRedirectURIsAttrValue {
			t.Errorf("created.Attributes[%q] = %q, want %q", postLogoutRedirectURIsAttrKey, got, postLogoutRedirectURIsAttrValue)
		}
	})

	t.Run("wanted-lookup error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, _, err := reconcileFrontendClient(context.Background(), kc, ""); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("create error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{})
			case http.MethodPost:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, _, err := reconcileFrontendClient(context.Background(), kc, ""); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("already-found repair PUT error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{{ID: "fe-id", ClientID: frontendClientID}})
			case http.MethodPut:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, _, err := reconcileFrontendClient(context.Background(), kc, ""); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// --- reconcileAudienceMapper ---

func TestReconcileAudienceMapper(t *testing.T) {
	t.Run("empty frontendInternalID is an error", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("no HTTP call expected")
		})
		if _, err := reconcileAudienceMapper(context.Background(), kc, ""); err == nil {
			t.Fatal("expected an error for an empty frontend internal id")
		}
	})

	t.Run("no existing mapper: created", func(t *testing.T) {
		var created kcProtocolMapperRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcProtocolMapperRep{})
			case http.MethodPost:
				_ = json.NewDecoder(r.Body).Decode(&created)
				w.WriteHeader(http.StatusCreated)
			}
		})
		changed, err := reconcileAudienceMapper(context.Background(), kc, "fe-id")
		if err != nil {
			t.Fatalf("reconcileAudienceMapper: %v", err)
		}
		if !changed || created.Config["included.client.audience"] != apiClientID {
			t.Errorf("changed=%v created=%+v, want a fresh mapper targeting %s", changed, created, apiClientID)
		}
	})

	t.Run("existing mapper already targets kiban-api: converged", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcProtocolMapperRep{{
				ID: "m1", ProtocolMapper: "oidc-audience-mapper",
				Config: map[string]string{"included.client.audience": apiClientID},
			}})
		})
		changed, err := reconcileAudienceMapper(context.Background(), kc, "fe-id")
		if err != nil {
			t.Fatalf("reconcileAudienceMapper: %v", err)
		}
		if changed {
			t.Error("changed = true, want false")
		}
	})

	t.Run("existing mapper targets a stale audience: updated", func(t *testing.T) {
		var updated kcProtocolMapperRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcProtocolMapperRep{{
					ID: "m1", ProtocolMapper: "oidc-audience-mapper",
					Config: map[string]string{"included.client.audience": "stale-api"},
				}})
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&updated)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, err := reconcileAudienceMapper(context.Background(), kc, "fe-id")
		if err != nil {
			t.Fatalf("reconcileAudienceMapper: %v", err)
		}
		if !changed || updated.Config["included.client.audience"] != apiClientID {
			t.Errorf("changed=%v updated=%+v, want retargeted to %s", changed, updated, apiClientID)
		}
	})

	t.Run("protocolMappers error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := reconcileAudienceMapper(context.Background(), kc, "fe-id"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("create error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcProtocolMapperRep{})
			case http.MethodPost:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := reconcileAudienceMapper(context.Background(), kc, "fe-id"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("update error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcProtocolMapperRep{{ID: "m1", ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{"included.client.audience": "stale-api"}}})
			case http.MethodPut:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := reconcileAudienceMapper(context.Background(), kc, "fe-id"); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// --- verifyMFAFlowWiring / verifyBrowserFlowStructure ---

func fixedBrowserFlowExecutions() []kcFlowExecutionRep {
	return []kcFlowExecutionRep{
		{Level: 0, Requirement: "REQUIRED", DisplayName: "kiban browser Auth"},
		{Level: 0, Requirement: "REQUIRED", ProviderID: mfaAuthenticatorID},
		{Level: 1, Requirement: "ALTERNATIVE", ProviderID: "auth-cookie"},
		{Level: 1, Requirement: "ALTERNATIVE", ProviderID: "identity-provider-redirector"},
		{Level: 1, Requirement: "ALTERNATIVE", DisplayName: "kiban browser Forms"},
	}
}

func TestVerifyBrowserFlowStructure(t *testing.T) {
	t.Run("the fixed structure passes", func(t *testing.T) {
		if err := verifyBrowserFlowStructure(fixedBrowserFlowExecutions()); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("the defect (REQUIRED mixed with ALTERNATIVE at level 0) is detected", func(t *testing.T) {
		broken := []kcFlowExecutionRep{
			{Level: 0, Requirement: "ALTERNATIVE", ProviderID: "auth-cookie"},
			{Level: 0, Requirement: "ALTERNATIVE", ProviderID: "identity-provider-redirector"},
			{Level: 0, Requirement: "ALTERNATIVE", DisplayName: "kiban browser Forms"},
			{Level: 0, Requirement: "REQUIRED", ProviderID: mfaAuthenticatorID},
		}
		err := verifyBrowserFlowStructure(broken)
		if err == nil {
			t.Fatal("expected the structural mix to be detected")
		}
	})

	t.Run("an all-ALTERNATIVE level and an all-REQUIRED level are both fine", func(t *testing.T) {
		fine := []kcFlowExecutionRep{
			{Level: 0, Requirement: "REQUIRED", ProviderID: "a"},
			{Level: 0, Requirement: "REQUIRED", ProviderID: "b"},
			{Level: 1, Requirement: "ALTERNATIVE", ProviderID: "c"},
			{Level: 1, Requirement: "ALTERNATIVE", ProviderID: "d"},
			{Level: 2, Requirement: "CONDITIONAL", ProviderID: "e"},
		}
		if err := verifyBrowserFlowStructure(fine); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestVerifyMFAFlowWiring(t *testing.T) {
	t.Run("converged", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/admin/realms/kiban":
				writeJSON(w, map[string]any{"browserFlow": browserFlowAlias})
			default:
				writeJSON(w, fixedBrowserFlowExecutions())
			}
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("getRealm error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("browserFlow mismatch after reconciliation is a hard error", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]any{"browserFlow": "some other flow"})
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("flowExecutions error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/realms/kiban":
				writeJSON(w, map[string]any{"browserFlow": browserFlowAlias})
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("structural defect detected before the requirement check even runs", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/realms/kiban":
				writeJSON(w, map[string]any{"browserFlow": browserFlowAlias})
			default:
				writeJSON(w, []kcFlowExecutionRep{
					{Level: 0, Requirement: "ALTERNATIVE", ProviderID: "auth-cookie"},
					{Level: 0, Requirement: "REQUIRED", ProviderID: mfaAuthenticatorID},
				})
			}
		})
		err := verifyMFAFlowWiring(context.Background(), kc)
		if err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("mfa authenticator present but not REQUIRED", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/realms/kiban":
				writeJSON(w, map[string]any{"browserFlow": browserFlowAlias})
			default:
				writeJSON(w, []kcFlowExecutionRep{
					{Level: 0, Requirement: "REQUIRED", DisplayName: "kiban browser Auth"},
					{Level: 0, Requirement: "DISABLED", ProviderID: mfaAuthenticatorID},
				})
			}
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("mfa authenticator missing entirely", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/realms/kiban":
				writeJSON(w, map[string]any{"browserFlow": browserFlowAlias})
			default:
				writeJSON(w, []kcFlowExecutionRep{{Level: 0, Requirement: "REQUIRED", ProviderID: "some-other-authenticator"}})
			}
		})
		if err := verifyMFAFlowWiring(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// --- verifyIdentityServiceRolesExact ---

func TestVerifyIdentityServiceRolesExact(t *testing.T) {
	// composite is the GET /users/{id}/role-mappings view; handlerFor's default carries only
	// realm-management roles (the exact set), the subtests below swap in foreign ones.
	composite := func(realmRoles []kcRoleRep, otherClientRoles map[string][]kcRoleRep) kcRoleMappingsRep {
		rep := kcRoleMappingsRep{RealmMappings: realmRoles, ClientMappings: map[string]struct {
			Mappings []kcRoleRep `json:"mappings"`
		}{}}
		rep.ClientMappings[realmManagementClientID] = struct {
			Mappings []kcRoleRep `json:"mappings"`
		}{Mappings: exactIdentityServiceRoleReps()}
		for client, roles := range otherClientRoles {
			rep.ClientMappings[client] = struct {
				Mappings []kcRoleRep `json:"mappings"`
			}{Mappings: roles}
		}
		return rep
	}
	handlerForComposite := func(assigned, available []kcRoleRep, all kcRoleMappingsRep) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings":
				writeJSON(w, all)
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id/available":
				writeJSON(w, available)
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id":
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				writeJSON(w, assigned)
			default:
				panic(fmt.Sprintf("unexpected %s %s", r.Method, r.URL.String()))
			}
		}
	}
	handlerFor := func(assigned, available []kcRoleRep) http.HandlerFunc {
		return handlerForComposite(assigned, available, composite(nil, nil))
	}

	exactRoles := func() []kcRoleRep {
		roles := make([]kcRoleRep, len(identityServiceRoles))
		for i, name := range identityServiceRoles {
			roles[i] = kcRoleRep{ID: "id-" + name, Name: name}
		}
		return roles
	}

	t.Run("already exact: converged", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", handlerFor(exactRoles(), nil))
		detail, err := verifyIdentityServiceRolesExact(context.Background(), kc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if detail == "" {
			t.Error("expected a non-empty detail")
		}
	})

	t.Run("extra role beyond the exact set: hard stop", func(t *testing.T) {
		withExtra := append(exactRoles(), kcRoleRep{ID: "id-extra", Name: "manage-realm"})
		kc := fakeKCFor(t, "kiban", handlerFor(withExtra, nil))
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error for an extra role")
		}
	})

	// The exact-role proof covers the whole composite view, not just realm-management.
	t.Run("a realm role beyond realm-management: hard stop", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", handlerForComposite(exactRoles(), nil, composite([]kcRoleRep{{ID: "r1", Name: "admin"}}, nil)))
		_, err := verifyIdentityServiceRolesExact(context.Background(), kc)
		if err == nil || !containsAll(err.Error(), "realm:admin") {
			t.Fatalf("expected a hard stop naming realm:admin, got %v", err)
		}
	})

	t.Run("another client's role: hard stop", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", handlerForComposite(exactRoles(), nil, composite(nil, map[string][]kcRoleRep{"broker": {{ID: "b1", Name: "read-token"}}})))
		_, err := verifyIdentityServiceRolesExact(context.Background(), kc)
		if err == nil || !containsAll(err.Error(), "broker:read-token") {
			t.Fatalf("expected a hard stop naming broker:read-token, got %v", err)
		}
	})

	t.Run("composite role-mappings error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings":
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("missing role: repaired via addClientRoles", func(t *testing.T) {
		missingOne := exactRoles()[:len(identityServiceRoles)-1] // drop the last wanted role
		available := []kcRoleRep{{ID: "id-" + identityServiceRoles[len(identityServiceRoles)-1], Name: identityServiceRoles[len(identityServiceRoles)-1]}}
		kc := fakeKCFor(t, "kiban", handlerFor(missingOne, available))
		detail, err := verifyIdentityServiceRolesExact(context.Background(), kc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if detail == "" {
			t.Error("expected a non-empty repair detail")
		}
	})

	t.Run("missing role that can't be resolved in available roles: an error", func(t *testing.T) {
		missingOne := exactRoles()[:len(identityServiceRoles)-1]
		kc := fakeKCFor(t, "kiban", handlerFor(missingOne, nil)) // available roles empty
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error when the missing role can't be resolved")
		}
	})

	t.Run("identity-service client not found", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{})
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("realm-management client not found", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("find identity-service client error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("serviceAccountUserID error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("assignedClientRoles error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id":
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("availableClientRoles error propagates", func(t *testing.T) {
		missingOne := exactRoles()[:len(identityServiceRoles)-1]
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id/available":
				w.WriteHeader(http.StatusInternalServerError)
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id":
				writeJSON(w, missingOne)
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("addClientRoles error propagates", func(t *testing.T) {
		missingOne := exactRoles()[:len(identityServiceRoles)-1]
		available := []kcRoleRep{{ID: "id-" + identityServiceRoles[len(identityServiceRoles)-1], Name: identityServiceRoles[len(identityServiceRoles)-1]}}
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.URL.Query().Get("clientId") == realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
				writeJSON(w, map[string]string{"id": "user-id"})
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id/available":
				writeJSON(w, available)
			case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id":
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				writeJSON(w, missingOne)
			}
		})
		if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// --- writeServiceSecrets ---

func TestWriteServiceSecrets(t *testing.T) {
	t.Run("SecretsDir empty: skipped, no HTTP call", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("no HTTP call expected")
		})
		detail, changed, err := writeServiceSecrets(context.Background(), kc, &Deps{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Error("changed = true, want false")
		}
		if detail == "" {
			t.Error("expected a non-empty skip detail")
		}
	})

	t.Run("client not found is an error", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{})
		})
		if _, _, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: t.TempDir()}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("find client error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, _, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: t.TempDir()}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("rotate: regenerates then writes, reporting ROTATED", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.Method == http.MethodPost:
				writeJSON(w, map[string]string{"value": "rotated-secret"})
			}
		})
		dir := t.TempDir()
		detail, changed, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: dir, RotateSecrets: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Error("changed = false, want true (rotation always writes)")
		}
		if !containsAll(detail, "ROTATED") {
			t.Errorf("detail = %q, want it to mention ROTATED", detail)
		}
	})

	t.Run("rotate error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, _, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: t.TempDir(), RotateSecrets: true}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("no rotation, no explicit secret: reads current secret and writes it (first time)", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.Method == http.MethodGet:
				writeJSON(w, map[string]string{"value": "read-secret"})
			}
		})
		dir := t.TempDir()
		detail, changed, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: dir})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Error("changed = false, want true (first write)")
		}
		if containsAll(detail, "ROTATED") {
			t.Errorf("detail = %q, should not mention ROTATED", detail)
		}
	})

	t.Run("read-secret error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.Method == http.MethodGet:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		if _, _, err := writeServiceSecrets(context.Background(), kc, &Deps{SecretsDir: t.TempDir()}); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("explicit IdentityClientSecret provided: no read, second run with the same secret is unchanged", func(t *testing.T) {
		var getCalls int
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Query().Get("clientId") == identityServiceClientID:
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case r.Method == http.MethodGet:
				getCalls++
			}
		})
		dir := t.TempDir()
		deps := &Deps{SecretsDir: dir, IdentityClientSecret: "explicit-secret"}

		_, changed1, err := writeServiceSecrets(context.Background(), kc, deps)
		if err != nil {
			t.Fatalf("first write: %v", err)
		}
		if !changed1 {
			t.Error("first write: changed = false, want true")
		}

		_, changed2, err := writeServiceSecrets(context.Background(), kc, deps)
		if err != nil {
			t.Fatalf("second write: %v", err)
		}
		if changed2 {
			t.Error("second write: changed = true, want false (same secret, unchanged file)")
		}
		if getCalls != 0 {
			t.Errorf("clientSecret GET called %d times, want 0 (explicit secret provided)", getCalls)
		}
	})
}

func containsAll(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// --- stringSlicesEqualUnordered ---

// TestStringSlicesEqualUnordered directly proves all three branches (differing length, same
// length but differing content after sort, fully equal) — the "same length, content differs"
// branch (realm.go:317's `if sa[i] != sb[i] { return false }` inside the loop) was previously
// only reachable indirectly through reconcileFrontendClient fixtures that always differed in
// LENGTH too, never in content alone at the same length.
func TestStringSlicesEqualUnordered(t *testing.T) {
	t.Run("differing length", func(t *testing.T) {
		if stringSlicesEqualUnordered([]string{"a"}, []string{"a", "b"}) {
			t.Error("want false for differing length")
		}
	})
	t.Run("same length, same content, different order", func(t *testing.T) {
		if !stringSlicesEqualUnordered([]string{"a", "b"}, []string{"b", "a"}) {
			t.Error("want true for same multiset, different order")
		}
	})
	t.Run("same length, content differs after sort", func(t *testing.T) {
		if stringSlicesEqualUnordered([]string{"a", "b"}, []string{"a", "c"}) {
			t.Error("want false when a sorted element pair differs")
		}
	})
}

// --- verifyIdentityServiceRolesExact: realm-management lookup HTTP error (distinct from "not
// found", which realm_fake_test.go's TestVerifyIdentityServiceRolesExact already covers) ---

func TestVerifyIdentityServiceRolesExact_RealmManagementLookupError(t *testing.T) {
	kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("clientId") == identityServiceClientID:
			writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
		case r.URL.Query().Get("clientId") == realmManagementClientID:
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
			writeJSON(w, map[string]string{"id": "user-id"})
		}
	})
	if _, err := verifyIdentityServiceRolesExact(context.Background(), kc); err == nil {
		t.Fatal("expected an error when the realm-management client lookup itself fails")
	}
}

// --- writeServiceSecrets: filesystem error branches ---

func TestWriteServiceSecrets_FilesystemErrors(t *testing.T) {
	t.Run("MkdirAll fails: SecretsDir path is blocked by an existing file", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
		})
		// A regular file sits where a path COMPONENT of SecretsDir needs to be a directory —
		// os.MkdirAll fails with ENOTDIR walking through it.
		parent := t.TempDir()
		blocker := filepath.Join(parent, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}
		deps := &Deps{SecretsDir: filepath.Join(blocker, "secrets"), IdentityClientSecret: "s"}
		if _, _, err := writeServiceSecrets(context.Background(), kc, deps); err == nil {
			t.Fatal("expected a MkdirAll error")
		}
	})

	t.Run("WriteFile fails: the secret's target path is itself a directory", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
		})
		dir := t.TempDir()
		// Pre-create a DIRECTORY at the exact path writeServiceSecrets will try to os.WriteFile
		// to — the write fails with EISDIR, MkdirAll itself is a no-op (already a directory).
		blockedPath := filepath.Join(dir, "keycloak-identity-client-secret")
		if err := os.MkdirAll(blockedPath, 0o700); err != nil {
			t.Fatalf("setup: %v", err)
		}
		deps := &Deps{SecretsDir: dir, IdentityClientSecret: "s"}
		if _, _, err := writeServiceSecrets(context.Background(), kc, deps); err == nil {
			t.Fatal("expected a WriteFile error")
		}
	})
}

// --- RealmStep.Run end-to-end (fake Keycloak) ---
//
// These prove Run()'s OWN orchestration — the applied-vs-converged aggregation across all six
// sub-steps, and each sub-step's error-wrap — deterministically, against a fake server, so this
// package's coverage does not depend on realm_test.go's live tests catching Run() at the right
// moment relative to the dev stack's own convergence state (the live tests always run against an
// ALREADY-converged realm once `make dev`'s own bootstrap container has run, so Run()'s "applied"
// aggregation branches and its error-wrap branches are otherwise only reachable by accidents of
// live timing).

// exactIdentityServiceRoleReps mirrors TestVerifyIdentityServiceRolesExact's own helper — kept as
// a separate copy here (this repo's established duplicate-don't-share convention for small
// per-test-file fixtures) so this file's Run()-level tests don't reach across to that function's
// closure.
func exactIdentityServiceRoleReps() []kcRoleRep {
	roles := make([]kcRoleRep, len(identityServiceRoles))
	for i, name := range identityServiceRoles {
		roles[i] = kcRoleRep{ID: "id-" + name, Name: name}
	}
	return roles
}

// runStepFakeConfig controls exactly one dimension of drift/failure per test — every other
// dimension stays at its "already converged" value — so each RealmStep.Run test isolates the one
// branch it's proving.
type runStepFakeConfig struct {
	// serviceClients are the KIBAN_SERVICE_CLIENTS ids the fake knows: absent on first lookup
	// (created, id "sc-<id>"), and their mapper list is empty (created).
	serviceClients            []string
	serviceClientLookupStatus int
	serviceMapperLookupStatus int
	realmSettingsStatus       int  // non-zero: GET /admin/realms/kiban fails with this status
	realmDisplayNameBad       bool // GET returns a wrong displayName, forcing a settings PUT (applied)

	apiClientLookupStatus int  // non-zero: GET clients?clientId=kiban-api fails
	apiClientNeedsRepair  bool // kiban-api comes back not bearer-only (forces a PUT, applied)

	frontendLookupStatus int  // non-zero: GET clients?clientId=kiban-frontend fails
	frontendNeedsRepair  bool // kiban-frontend comes back with wrong redirects (forces a PUT, applied)

	mapperLookupStatus int  // non-zero: GET protocol-mappers/models fails
	mapperNeedsRepair  bool // existing mapper targets a stale audience (forces a PUT, applied)

	mfaFlowExecutionsStatus int // non-zero: GET flow executions fails (surfaces as verifyMFAFlowWiring's error)

	directGrantFlowMissing bool // the realm has no "kiban direct grant" flow yet (forces copy + add + REQUIRED + realm bind, applied)

	userProfileNeedsRepair bool // profile lacks the kiban.login_security.* attributes (forces a PUT, applied)

	rolesLookupStatus int // non-zero: GET clients?clientId=kiban-identity-service fails (surfaces as verifyIdentityServiceRolesExact's error)

	secretsClientLookupStatus int // non-zero: GET clients?clientId=kiban-identity-service fails during writeServiceSecrets
}

func realmStepFakeServer(t *testing.T, cfg runStepFakeConfig) *httptest.Server {
	t.Helper()
	redirects, origins := frontendOrigins("")
	// Run() looks up kiban-identity-service TWICE (once in verifyIdentityServiceRolesExact, once
	// again in writeServiceSecrets) — a call counter lets the "secrets" error case fail only the
	// SECOND lookup while the first (step 5) still succeeds normally.
	identityServiceLookupCalls := 0
	// Direct-grant flow repair progress (directGrantFlowMissing): each admin call the repair makes
	// flips the fake's state so the next read reflects it.
	var directGrantCopied, directGrantMFAAdded, directGrantMFARequired bool

	var srv *httptest.Server
	srvURL := func() string { return srv.URL }
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-token"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		// 1. Realm settings.
		case r.URL.Path == "/admin/realms/kiban" && r.Method == http.MethodGet:
			if cfg.realmSettingsStatus != 0 {
				w.WriteHeader(cfg.realmSettingsStatus)
				return
			}
			current := map[string]any{}
			for k, v := range realmTargetSettings {
				current[k] = v
			}
			if cfg.realmDisplayNameBad {
				current["displayName"] = "Wrong Name"
			}
			current["directGrantFlow"] = directGrantFlowAlias
			if cfg.directGrantFlowMissing {
				current["directGrantFlow"] = builtinDirectGrantAlias
			}
			writeJSON(w, current)
		case r.URL.Path == "/admin/realms/kiban" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)

		// 2/3. Client lookups (kiban-api, kiban-frontend, kiban-identity-service, realm-management).
		case r.URL.Path == "/admin/realms/kiban/clients" && r.Method == http.MethodGet:
			switch r.URL.Query().Get("clientId") {
			case apiClientID:
				if cfg.apiClientLookupStatus != 0 {
					w.WriteHeader(cfg.apiClientLookupStatus)
					return
				}
				writeJSON(w, []kcClientRep{{ID: "api-id", ClientID: apiClientID, BearerOnly: !cfg.apiClientNeedsRepair, Enabled: true}})
			case frontendClientID:
				if cfg.frontendLookupStatus != 0 {
					w.WriteHeader(cfg.frontendLookupStatus)
					return
				}
				fe := kcClientRep{
					ID: "fe-id", ClientID: frontendClientID, PublicClient: true, StandardFlowEnabled: true, RedirectUris: redirects, WebOrigins: origins,
					Attributes: map[string]string{postLogoutRedirectURIsAttrKey: postLogoutRedirectURIsAttrValue},
				}
				if cfg.frontendNeedsRepair {
					fe.RedirectUris = []string{"http://stale.example/*"}
					fe.WebOrigins = []string{"http://stale.example"}
				}
				writeJSON(w, []kcClientRep{fe})
			case identityServiceClientID:
				identityServiceLookupCalls++
				if identityServiceLookupCalls == 1 && cfg.rolesLookupStatus != 0 {
					w.WriteHeader(cfg.rolesLookupStatus)
					return
				}
				if identityServiceLookupCalls == 2 && cfg.secretsClientLookupStatus != 0 {
					w.WriteHeader(cfg.secretsClientLookupStatus)
					return
				}
				writeJSON(w, []kcClientRep{{ID: "svc-id", ClientID: identityServiceClientID}})
			case realmManagementClientID:
				writeJSON(w, []kcClientRep{{ID: "rm-id", ClientID: realmManagementClientID}})
			default:
				if cfg.serviceClientLookupStatus != 0 && slices.Contains(cfg.serviceClients, r.URL.Query().Get("clientId")) {
					w.WriteHeader(cfg.serviceClientLookupStatus)
					return
				}
				writeJSON(w, []kcClientRep{})
			}
		// 3c. Service clients: created fresh, then given the audience mapper.
		case r.URL.Path == "/admin/realms/kiban/clients" && r.Method == http.MethodPost:
			var rep kcClientRep
			_ = json.NewDecoder(r.Body).Decode(&rep)
			if !slices.Contains(cfg.serviceClients, rep.ClientID) || rep.PublicClient || !rep.ServiceAccountsEnabled {
				t.Errorf("unexpected client create %+v", rep)
			}
			w.Header().Set("Location", srvURL()+"/admin/realms/kiban/clients/sc-"+rep.ClientID)
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/kiban/clients/sc-") && strings.HasSuffix(r.URL.Path, "/protocol-mappers/models") && r.Method == http.MethodGet:
			if cfg.serviceMapperLookupStatus != 0 {
				w.WriteHeader(cfg.serviceMapperLookupStatus)
				return
			}
			writeJSON(w, []kcProtocolMapperRep{})
		case strings.HasPrefix(r.URL.Path, "/admin/realms/kiban/clients/sc-") && strings.HasSuffix(r.URL.Path, "/protocol-mappers/models") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/kiban/clients/") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)

		// 3b. Audience mapper.
		case r.URL.Path == "/admin/realms/kiban/clients/fe-id/protocol-mappers/models" && r.Method == http.MethodGet:
			if cfg.mapperLookupStatus != 0 {
				w.WriteHeader(cfg.mapperLookupStatus)
				return
			}
			audience := apiClientID
			if cfg.mapperNeedsRepair {
				audience = "stale-api"
			}
			writeJSON(w, []kcProtocolMapperRep{{ID: "m1", ProtocolMapper: "oidc-audience-mapper", Config: map[string]string{"included.client.audience": audience}}})
		case r.URL.Path == "/admin/realms/kiban/clients/fe-id/protocol-mappers/models" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/kiban/clients/fe-id/protocol-mappers/models/m1" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)

		// 4. MFA flow wiring.
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban browser/executions":
			if cfg.mfaFlowExecutionsStatus != 0 {
				w.WriteHeader(cfg.mfaFlowExecutionsStatus)
				return
			}
			writeJSON(w, fixedBrowserFlowExecutions())

		// 4a. Direct-grant MFA flow: converged unless directGrantFlowMissing, in which case the
		// flow appears only after the copy, the authenticator only after the add, and its
		// requirement reads REQUIRED only after the PUT (the repair sequence in order).
		case r.URL.Path == "/admin/realms/kiban/authentication/flows" && r.Method == http.MethodGet:
			flows := []map[string]any{{"alias": browserFlowAlias}, {"alias": builtinDirectGrantAlias}}
			if !cfg.directGrantFlowMissing || directGrantCopied {
				flows = append(flows, map[string]any{"alias": directGrantFlowAlias})
			}
			writeJSON(w, flows)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/direct grant/copy" && r.Method == http.MethodPost:
			directGrantCopied = true
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions" && r.Method == http.MethodGet:
			execs := []kcFlowExecutionRep{
				{ID: "dg-1", Level: 0, Requirement: "REQUIRED", ProviderID: "direct-grant-validate-username"},
				{ID: "dg-2", Level: 0, Requirement: "REQUIRED", ProviderID: "direct-grant-validate-password"},
			}
			switch {
			case !cfg.directGrantFlowMissing:
				execs = append(execs, kcFlowExecutionRep{ID: "dg-mfa", Level: 0, Requirement: "REQUIRED", ProviderID: mfaAuthenticatorID})
			case directGrantMFAAdded:
				req := "DISABLED"
				if directGrantMFARequired {
					req = "REQUIRED"
				}
				execs = append(execs, kcFlowExecutionRep{ID: "dg-mfa", Level: 0, Requirement: req, ProviderID: mfaAuthenticatorID})
			}
			writeJSON(w, execs)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions/execution" && r.Method == http.MethodPost:
			directGrantMFAAdded = true
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions" && r.Method == http.MethodPut:
			directGrantMFARequired = true
			w.WriteHeader(http.StatusAccepted)

		// 4b. User-profile MFA attributes (managed admin-only declarations).
		case r.URL.Path == "/admin/realms/kiban/users/profile" && r.Method == http.MethodGet:
			attrs := []map[string]any{
				{"name": "username"}, {"name": "email"},
			}
			if !cfg.userProfileNeedsRepair {
				for _, name := range userProfileManagedAttributes {
					attrs = append(attrs, map[string]any{
						"name":        name,
						"permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}},
					})
				}
			}
			writeJSON(w, map[string]any{"attributes": attrs})
		case r.URL.Path == "/admin/realms/kiban/users/profile" && r.Method == http.MethodPut:
			if !cfg.userProfileNeedsRepair {
				t.Errorf("PUT /users/profile on an already-converged profile — reconcile should have been a no-op")
			}
			w.WriteHeader(http.StatusOK)

		// 5. Identity service account role verification.
		case r.URL.Path == "/admin/realms/kiban/clients/svc-id/service-account-user":
			writeJSON(w, map[string]string{"id": "user-id"})
		case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings":
			writeJSON(w, map[string]any{"realmMappings": []any{}, "clientMappings": map[string]any{
				realmManagementClientID: map[string]any{"mappings": exactIdentityServiceRoleReps()},
			}})
		case r.URL.Path == "/admin/realms/kiban/users/user-id/role-mappings/clients/rm-id":
			writeJSON(w, exactIdentityServiceRoleReps())

		// 6. Secrets.
		case r.URL.Path == "/admin/realms/kiban/clients/svc-id/client-secret" && r.Method == http.MethodGet:
			writeJSON(w, map[string]string{"value": "the-secret"})

		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
		}
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runStepFakeDeps(t *testing.T, cfg runStepFakeConfig) *Deps {
	t.Helper()
	srv := realmStepFakeServer(t, cfg)
	dir := t.TempDir()
	// Pre-seed the secret file so writeServiceSecrets converges (matches deps.IdentityClientSecret
	// below) unless the test is specifically proving a secrets-path error.
	if err := os.WriteFile(filepath.Join(dir, "keycloak-identity-client-secret"), []byte("the-secret"), 0o600); err != nil {
		t.Fatalf("pre-seed secret file: %v", err)
	}
	return &Deps{
		HTTPClient:               srv.Client(),
		KeycloakAdminBaseURL:     srv.URL,
		KeycloakRealm:            "kiban",
		KCBootstrapAdminUsername: "admin",
		KCBootstrapAdminPassword: "admin",
		KibanDomain:              "",
		IdentityClientSecret:     "the-secret",
		SecretsDir:               dir,
		ServiceClients:           cfg.serviceClients,
	}
}

func TestRealmStep_Run_ServiceClientsApplied(t *testing.T) {
	deps := runStepFakeDeps(t, runStepFakeConfig{serviceClients: []string{"tokidesk-worker", "tokidesk-mailer"}})
	outcome, detail, err := RealmStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("outcome = %s, want applied: %s", outcome, detail)
	}
	for _, want := range []string{"service client tokidesk-worker: applied", "service client tokidesk-mailer: applied"} {
		if !containsAll(detail, want) {
			t.Errorf("detail = %q, want it to contain %q", detail, want)
		}
	}
}

func TestRealmStep_Run_FullyConverged(t *testing.T) {
	deps := runStepFakeDeps(t, runStepFakeConfig{})
	outcome, detail, err := RealmStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged: %s", outcome, detail)
	}
}

func TestRealmStep_Run_FullyApplied(t *testing.T) {
	deps := runStepFakeDeps(t, runStepFakeConfig{
		realmDisplayNameBad:    true,
		apiClientNeedsRepair:   true,
		frontendNeedsRepair:    true,
		mapperNeedsRepair:      true,
		userProfileNeedsRepair: true,
		directGrantFlowMissing: true,
	})
	outcome, detail, err := RealmStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("outcome = %s, want applied: %s", outcome, detail)
	}
	for _, want := range []string{"settings: applied", "client " + apiClientID + ": applied", "client " + frontendClientID + ": applied", "audience mapper: applied", "direct-grant MFA flow: applied", "user-profile MFA attributes: applied"} {
		if !containsAll(detail, want) {
			t.Errorf("detail = %q, want it to contain %q", detail, want)
		}
	}
}

func TestRealmStep_Run_ErrorPropagation(t *testing.T) {
	cases := []struct {
		name   string
		cfg    runStepFakeConfig
		wantIn string // substring Run()'s own wrapped error must contain
	}{
		{"realm settings", runStepFakeConfig{realmSettingsStatus: http.StatusInternalServerError}, "realm: settings:"},
		{"api client", runStepFakeConfig{apiClientLookupStatus: http.StatusInternalServerError}, "realm: " + apiClientID + " client:"},
		{"frontend client", runStepFakeConfig{frontendLookupStatus: http.StatusInternalServerError}, "realm: " + frontendClientID + " client:"},
		{"audience mapper", runStepFakeConfig{mapperLookupStatus: http.StatusInternalServerError}, "realm: audience mapper:"},
		{"MFA flow wiring", runStepFakeConfig{mfaFlowExecutionsStatus: http.StatusInternalServerError}, "realm: MFA flow wiring:"},
		{"identity service roles", runStepFakeConfig{rolesLookupStatus: http.StatusInternalServerError}, "find client " + identityServiceClientID},
		{"secrets", runStepFakeConfig{secretsClientLookupStatus: http.StatusInternalServerError}, "realm: secrets:"},
		{"service client", runStepFakeConfig{serviceClients: []string{"w"}, serviceClientLookupStatus: http.StatusInternalServerError}, "realm: service client w:"},
		{"service client mapper", runStepFakeConfig{serviceClients: []string{"w"}, serviceMapperLookupStatus: http.StatusInternalServerError}, "realm: service client w audience mapper:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := runStepFakeDeps(t, tc.cfg)
			outcome, _, err := RealmStep{}.Run(context.Background(), deps)
			if err == nil {
				t.Fatal("expected an error")
			}
			if outcome != OutcomeFailed {
				t.Errorf("outcome = %s, want failed", outcome)
			}
			if !containsAll(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantIn)
			}
		})
	}
}

// --- RealmStep.Name / RealmStep.Run (skipped path) ---

func TestRealmStep_Name(t *testing.T) {
	if got, want := (RealmStep{}).Name(), "realm"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestRealmStep_Run_SkippedWhenNoKeycloakAdminBaseURL(t *testing.T) {
	outcome, detail, err := RealmStep{}.Run(context.Background(), &Deps{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != OutcomeConverged {
		t.Errorf("outcome = %s, want converged", outcome)
	}
	if detail == "" {
		t.Error("expected a non-empty skip detail")
	}
}
