// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// fakeIdentityServer is a minimal stand-in for identity's real HTTP surface, backing the one
// endpoint IdentityClient calls for decision.SubjectSource/KeycloakSource: GET
// .../users/{kcSub}/state. Every kcSub in roles is a known, active, enabled user; the role
// lists are what buildHTTPService (http_test.go) seeds as `system:platform#superadmin` tuples —
// the platform role's only record lives in authz's own store, never in identity.
func fakeIdentityServer(t *testing.T, roles map[string][]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/identity/users/{kcSub}/state", func(w http.ResponseWriter, r *http.Request) {
		kcSub := r.PathValue("kcSub")
		if _, known := roles[kcSub]; !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestData(w, map[string]string{"lifecycle": "active", "kcEnabled": "true"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeTestData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// TestDecisionGlobalPlatformRoleWiredToEngine proves the real enginePlatformRoleSource (step
// 4's source: an engine check on the `system:platform#superadmin` tuple) makes
// decision.Evaluate's global-scope step 4 return PLATFORM_ROLE_REQUIRED for a user with no tuple
// and ALLOWED for one with it — never DEPENDENCY_UNAVAILABLE — with no fake PlatformRoleSource
// involved anywhere in the chain. Any role other than kiban-superadmin is simply not held.
func TestDecisionGlobalPlatformRoleWiredToEngine(t *testing.T) {
	const roleLess, superadmin = "engine-role-less-user", "engine-superadmin-user"
	svc, _, _ := buildHTTPService(t, map[string][]string{roleLess: nil, superadmin: {"kiban-superadmin"}}, nil, nil, nil, false)

	decider, err := svc.buildDecider(context.Background())
	if err != nil {
		t.Fatalf("build decider: %v", err)
	}

	t.Run("user without the tuple is denied PLATFORM_ROLE_REQUIRED", func(t *testing.T) {
		got := decider.Evaluate(context.Background(), decision.Request{
			SubjectID: roleLess, FeatureKey: "auth.platform_administration.access",
			Scope: decision.ScopeGlobal, RequiredPlatformRole: "kiban-superadmin",
		})
		if got.Allowed || got.Reason != decision.ReasonPlatformRoleRequired {
			t.Fatalf("reason = %s (allowed=%v), want PLATFORM_ROLE_REQUIRED", got.Reason, got.Allowed)
		}
	})

	t.Run("superadmin tuple holder is allowed", func(t *testing.T) {
		got := decider.Evaluate(context.Background(), decision.Request{
			SubjectID: superadmin, FeatureKey: "auth.platform_administration.access",
			Scope: decision.ScopeGlobal, RequiredPlatformRole: "kiban-superadmin",
		})
		if !got.Allowed || got.Reason != decision.ReasonAllowed {
			t.Fatalf("expected ALLOWED, got reason=%s evidence=%+v", got.Reason, got.Evidence)
		}
	})

	t.Run("an unknown role name is never held, even by the superadmin", func(t *testing.T) {
		got := decider.Evaluate(context.Background(), decision.Request{
			SubjectID: superadmin, FeatureKey: "auth.platform_administration.access",
			Scope: decision.ScopeGlobal, RequiredPlatformRole: "some-other-role",
		})
		if got.Allowed || got.Reason != decision.ReasonPlatformRoleRequired {
			t.Fatalf("reason = %s, want PLATFORM_ROLE_REQUIRED for an unknown role", got.Reason)
		}
	})

	t.Run("unknown kcSub is uncertain at subject lookup, not a fabricated allow/deny", func(t *testing.T) {
		got := decider.Evaluate(context.Background(), decision.Request{
			SubjectID: "never-resolved-user", FeatureKey: "auth.platform_administration.access",
			Scope: decision.ScopeGlobal, RequiredPlatformRole: "kiban-superadmin",
		})
		if got.Reason != decision.ReasonAuthUserNotFound {
			t.Fatalf("reason = %s, want AUTH_USER_NOT_FOUND", got.Reason)
		}
	})
}
