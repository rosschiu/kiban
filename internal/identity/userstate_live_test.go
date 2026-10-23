// SPDX-License-Identifier: Apache-2.0

//go:build live

package identity

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestLive_KCDBReader_ReadsKeycloaksTable proves the direct read: kiban_kcread (created by
// infra/postgres-init at initdb, default privileges on the tables Keycloak creates later) sees
// the identity service account's enabled flag, answers unknown for an id the realm does not
// have, and agrees with the admin REST API on the same user.
func TestLive_KCDBReader_ReadsKeycloaksTable(t *testing.T) {
	cfg := loadKCConfig(t)
	ctx := context.Background()
	dsn := "postgres://kiban_kcread:" + testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD") + "@127.0.0.1:" + testEnv(t, "POSTGRES_HOST_PORT") + "/keycloak?sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as kiban_kcread: %v", err)
	}
	defer pool.Close()
	reader, err := NewKCDBReader(ctx, pool, cfg.realm)
	if err != nil {
		t.Fatalf("NewKCDBReader (is the test stack's cluster initialised with kiban_kcread?): %v", err)
	}

	adminClient := NewAdminClient(&http.Client{Timeout: 5 * time.Second}, cfg.baseURL, cfg.realm, "kiban-identity-service", cfg.clientSecret)
	bearer, err := adminClient.token(ctx)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	verifier, err := NewTokenVerifier(ctx, cfg.baseURL+"/realms/"+cfg.realm+"/protocol/openid-connect/certs", cfg.baseURL+"/realms/"+cfg.realm, "realm-management")
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	claims, err := verifier.Verify(ctx, bearer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	fromDB, err := reader.UserEnabled(ctx, claims.Sub)
	if err != nil || fromDB != KCStateTrue {
		t.Fatalf("direct read of the service account = %s, %v; want true", fromDB, err)
	}
	fromAPI, _ := adminClient.UserEnabled(ctx, claims.Sub)
	if fromAPI != fromDB {
		t.Fatalf("admin API says %s, database says %s", fromAPI, fromDB)
	}
	if st, err := reader.UserEnabled(ctx, "00000000-0000-0000-0000-000000000000"); st != KCStateUnknown || err == nil {
		t.Fatalf("unknown id = %s, %v; want unknown with an error", st, err)
	}
	if _, err := NewKCDBReader(ctx, pool, "no-such-realm"); err == nil {
		t.Fatal("a missing realm must fail the probe")
	}
}
