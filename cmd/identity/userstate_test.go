// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/identity"
)

// TestUserStateSource_DirectReadOrCachedAPI proves the three outcomes of the start-up choice:
// no Keycloak database configured, the database configured but unreachable (an upgraded
// cluster without the grant, Keycloak elsewhere), and the shipped shape where the direct read
// is taken.
func TestUserStateSource_DirectReadOrCachedAPI(t *testing.T) {
	setIdentityEnv(t)
	values := map[string]string{}
	for _, k := range []string{"KIBAN_IDENTITY_DB_HOST", "KIBAN_IDENTITY_DB_PORT", "KIBAN_IDENTITY_DB_PASSWORD", "KEYCLOAK_REALM", "KEYCLOAK_BASE_URL", "KEYCLOAK_IDENTITY_CLIENT_SECRET"} {
		values[k] = os.Getenv(k)
	}
	values["KIBAN_USER_STATE_CACHE_SECONDS"] = "not-a-number" // falls back to the default
	admin := identity.NewAdminClient(&http.Client{Timeout: 5 * time.Second}, values["KEYCLOAK_BASE_URL"], values["KEYCLOAK_REALM"], "kiban-identity-service", values["KEYCLOAK_IDENTITY_CLIENT_SECRET"])
	ctx := context.Background()

	values["KEYCLOAK_DB_NAME"] = ""
	if _, ok := userStateSource(ctx, testLogger(), values, admin).(*identity.CachedUserState); !ok {
		t.Fatal("no database configured: want the cached admin API")
	}
	values["KEYCLOAK_DB_NAME"] = "no-such-database"
	if _, ok := userStateSource(ctx, testLogger(), values, admin).(*identity.CachedUserState); !ok {
		t.Fatal("database unreachable: want the cached admin API fallback")
	}
	values["KEYCLOAK_DB_NAME"] = "keycloak"
	if _, ok := userStateSource(ctx, testLogger(), values, admin).(*identity.KCDBReader); !ok {
		t.Fatal("the test stack shares its Postgres with Keycloak: want the direct read")
	}
}
