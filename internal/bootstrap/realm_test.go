// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/livestack"
)

// realmTestDeps builds a Deps wired to the real dev-stack Keycloak (.env, `make dev`
// already up).
func realmTestDeps(t *testing.T) *Deps {
	t.Helper()
	if livestack.TargetsLiveStack() {
		t.Fatal(livestack.RefusalMessage)
	}
	return &Deps{
		HTTPClient:               &http.Client{Timeout: 15 * time.Second},
		KeycloakAdminBaseURL:     "http://127.0.0.1:" + bootstrapTestEnv(t, "KEYCLOAK_HOST_PORT"),
		KeycloakRealm:            bootstrapTestEnv(t, "KEYCLOAK_REALM"),
		KCBootstrapAdminUsername: bootstrapTestEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME"),
		KCBootstrapAdminPassword: bootstrapTestEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD"),
		KibanDomain:              "", // dev: fall back to the loopback origins already imported
		IdentityClientSecret:     bootstrapTestEnv(t, "KEYCLOAK_IDENTITY_CLIENT_SECRET"),
		SecretsDir:               t.TempDir(),
	}
}

// TestRealm_RunTwiceConverges runs RealmStep against the real dev Keycloak, then
// run it again — the second run must be all-converged (Outcome Converged, no "applied" items in
// its own sub-steps beyond what the first run already fixed).
func TestRealm_RunTwiceConverges(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()

	first, detail1, err := RealmStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("first run failed: %v (detail: %s)", err, detail1)
	}
	t.Logf("first run: outcome=%s detail=%s", first, detail1)

	second, detail2, err := RealmStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("second run failed: %v (detail: %s)", err, detail2)
	}
	t.Logf("second run: outcome=%s detail=%s", second, detail2)
	if second != OutcomeConverged {
		t.Fatalf("second run outcome = %s, want converged: %s", second, detail2)
	}

	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	if _, found, err := kc.findClientByClientID(ctx, apiClientID); err != nil || !found {
		t.Fatalf("client %s not found after reconciliation: found=%v err=%v", apiClientID, found, err)
	}
	feRep, found, err := kc.findClientByClientID(ctx, frontendClientID)
	if err != nil || !found {
		t.Fatalf("client %s not found after reconciliation: found=%v err=%v", frontendClientID, found, err)
	}

	mappers, err := kc.protocolMappers(ctx, feRep.ID)
	if err != nil {
		t.Fatalf("read protocol mappers: %v", err)
	}
	var sawAudience bool
	for _, m := range mappers {
		if m.ProtocolMapper == "oidc-audience-mapper" {
			sawAudience = true
			if m.Config["included.client.audience"] != apiClientID {
				t.Fatalf("audience mapper targets %q, want %q", m.Config["included.client.audience"], apiClientID)
			}
		}
	}
	if !sawAudience {
		t.Fatal("no oidc-audience-mapper found on kiban-frontend")
	}

	realm, err := kc.getRealm(ctx)
	if err != nil {
		t.Fatalf("get realm: %v", err)
	}
	if bf, _ := realm["browserFlow"].(string); bf != browserFlowAlias {
		t.Fatalf("realm browserFlow = %q, want %q", bf, browserFlowAlias)
	}
}

// TestRealm_ManualTweakIsRepairedAndReported: a manual realm tweak (redirect URIs edited by
// hand, simulating drift) is repaired on the NEXT run, which reports it (Outcome Applied with a
// detail naming the repaired item).
func TestRealm_ManualTweakIsRepairedAndReported(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()

	baselineStep := RealmStep{}
	if _, _, err := baselineStep.Run(ctx, deps); err != nil {
		t.Fatalf("baseline run failed: %v", err)
	}

	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)
	rep, found, err := kc.findClientByClientID(ctx, frontendClientID)
	if err != nil || !found {
		t.Fatalf("client %s not found: found=%v err=%v", frontendClientID, found, err)
	}

	// Manual tweak: drop the tenant's redirect URIs to something wrong.
	tweaked := rep
	tweaked.RedirectUris = []string{"http://manual-tweak.example/*"}
	if err := kc.updateClient(ctx, rep.ID, tweaked); err != nil {
		t.Fatalf("simulate manual tweak: %v", err)
	}

	outcome, detail, err := RealmStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("repair run failed: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("repair run outcome = %s, want applied: %s", outcome, detail)
	}
	if !strings.Contains(detail, "client "+frontendClientID+": applied") {
		t.Fatalf("repair detail does not name the repaired client: %s", detail)
	}

	repaired, found, err := kc.findClientByClientID(ctx, frontendClientID)
	if err != nil || !found {
		t.Fatalf("client %s not found after repair: found=%v err=%v", frontendClientID, found, err)
	}
	if stringSlicesEqualUnordered(repaired.RedirectUris, tweaked.RedirectUris) {
		t.Fatalf("redirect URIs still show the manual tweak after repair: %v", repaired.RedirectUris)
	}

	// Fourth run: converged again.
	final, _, err := RealmStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("final run failed: %v", err)
	}
	if final != OutcomeConverged {
		t.Fatalf("final run outcome = %s, want converged", final)
	}
}

// TestRealm_IdentityServiceRolesExactNoExtras proves the exact-role verification converges (no
// extras) against the realm imported by infra/keycloak-build/realm-kiban.json.
func TestRealm_IdentityServiceRolesExactNoExtras(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()
	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	detail, err := verifyIdentityServiceRolesExact(ctx, kc)
	if err != nil {
		t.Fatalf("exact-role verification failed: %v", err)
	}
	t.Logf("detail: %s", detail)
}
