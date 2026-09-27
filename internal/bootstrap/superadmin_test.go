// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/livestack"
)

// bootstrapServicePool connects to the shared dev-stack database (one Postgres instance,
// schema-per-service) as the given runtime role.
func bootstrapServicePool(t *testing.T, role, password string) *pgxpool.Pool {
	return livestack.Pool(t, role, password)
}

// superadminTestDeps builds a Deps wired to the real dev-stack Keycloak + the owner-role DB
// connection SuperadminStep writes through. Each test run creates a UNIQUE username
// (time-suffixed) so repeated `go test` invocations never collide with a superadmin a previous
// run already created. countSuperadmins reads the step's marker, the `system:platform#superadmin`
// tuple count.
func superadminTestDeps(t *testing.T) (*Deps, func() (int, error)) {
	t.Helper()
	pool := bootstrapAdminPool(t)

	deps := &Deps{
		HTTPClient:               &http.Client{Timeout: 15 * time.Second},
		KeycloakAdminBaseURL:     "http://127.0.0.1:" + bootstrapTestEnv(t, "KEYCLOAK_HOST_PORT"),
		KeycloakRealm:            bootstrapTestEnv(t, "KEYCLOAK_REALM"),
		KCBootstrapAdminUsername: bootstrapTestEnv(t, "KC_BOOTSTRAP_ADMIN_USERNAME"),
		KCBootstrapAdminPassword: bootstrapTestEnv(t, "KC_BOOTSTRAP_ADMIN_PASSWORD"),
		Pool:                     pool,
	}
	return deps, func() (int, error) { return store.CountSuperadmins(context.Background(), pool) }
}

// TestSuperadmin_FirstRunCreatesSecondRunSkips: no superadmin exists yet (this
// test's own tuple-count check gates it — see the t.Skip below when one already exists from a prior
// bootstrap run against this same dev stack) ⇒ first run creates one (Applied); second run is a
// no-op (Converged, "skipped").
func TestSuperadmin_FirstRunCreatesSecondRunSkips(t *testing.T) {
	deps, countSuperadmins := superadminTestDeps(t)
	ctx := context.Background()

	before, err := countSuperadmins()
	if err != nil {
		t.Fatalf("count superadmins before: %v", err)
	}
	if before > 0 {
		t.Skipf("a superadmin already exists (n=%d) on this dev stack — one-time-creation semantics mean this test only proves something new on a stack with zero superadmins; TestSuperadmin_SecondRunAlwaysSkipsWhenOneExists below covers the steady-state case instead", before)
	}

	deps.SuperadminUsername = fmt.Sprintf("test-superadmin-%d", time.Now().UnixNano())
	deps.SuperadminEmail = deps.SuperadminUsername + "@example.invalid"
	deps.SuperadminPassword = "Test-Temp-Passw0rd!"

	first, detail1, err := SuperadminStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("first run failed: %v (detail: %s)", err, detail1)
	}
	if first != OutcomeApplied {
		t.Fatalf("first run outcome = %s, want applied: %s", first, detail1)
	}
	t.Logf("first run: %s", detail1)

	after, err := countSuperadmins()
	if err != nil {
		t.Fatalf("count superadmins after: %v", err)
	}
	if after != before+1 {
		t.Fatalf("superadmin count after first run = %d, want %d", after, before+1)
	}

	second, detail2, err := SuperadminStep{}.Run(ctx, deps)
	if err != nil {
		t.Fatalf("second run failed: %v (detail: %s)", err, detail2)
	}
	if second != OutcomeConverged {
		t.Fatalf("second run outcome = %s, want converged (already-created superadmin must be skipped): %s", second, detail2)
	}
	t.Logf("second run: %s", detail2)

	afterSecond, err := countSuperadmins()
	if err != nil {
		t.Fatalf("count superadmins after second run: %v", err)
	}
	if afterSecond != after {
		t.Fatalf("second run changed the superadmin count: before=%d after=%d — must be a true no-op", after, afterSecond)
	}
}

// TestSuperadmin_SecondRunAlwaysSkipsWhenOneExists proves the steady-state case unconditionally
// (no t.Skip): whatever the current superadmin count is, running SuperadminStep with NO
// Keycloak/username configured still converges as "skipped" as long as count > 0 — the marker
// check happens before anything Keycloak-related is touched.
func TestSuperadmin_SecondRunAlwaysSkipsWhenOneExists(t *testing.T) {
	deps, countSuperadmins := superadminTestDeps(t)
	ctx := context.Background()

	count, err := countSuperadmins()
	if err != nil {
		t.Fatalf("count superadmins: %v", err)
	}
	if count == 0 {
		// Seed one directly via the same in-process path SuperadminStep itself uses, so this
		// test doesn't depend on run order relative to TestSuperadmin_FirstRunCreatesSecondRunSkips.
		seedStep := SuperadminStep{}
		if _, _, err := seedStep.Run(ctx, &Deps{
			HTTPClient:               deps.HTTPClient,
			KeycloakAdminBaseURL:     deps.KeycloakAdminBaseURL,
			KeycloakRealm:            deps.KeycloakRealm,
			KCBootstrapAdminUsername: deps.KCBootstrapAdminUsername,
			KCBootstrapAdminPassword: deps.KCBootstrapAdminPassword,
			Pool:                     deps.Pool,
			SuperadminUsername:       fmt.Sprintf("test-superadmin-seed-%d", time.Now().UnixNano()),
			SuperadminEmail:          "test-superadmin-seed@example.invalid",
			SuperadminPassword:       "Test-Temp-Passw0rd!",
		}); err != nil {
			t.Fatalf("seed a superadmin for this test: %v", err)
		}
	}

	// Deliberately no Keycloak config on this Deps — if the step tried to create a Keycloak
	// user it would fail loudly (KeycloakAdminBaseURL == ""); converging without touching
	// Keycloak at all is exactly what "skipped" must mean.
	outcome, detail, err := SuperadminStep{}.Run(ctx, &Deps{Pool: deps.Pool})
	if err != nil {
		t.Fatalf("run failed: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged: %s", outcome, detail)
	}
}
