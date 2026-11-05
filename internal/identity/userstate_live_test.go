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

	// A disabled user reads as false: a throwaway row written as Keycloak's own role, never a
	// real account, removed again at the end.
	owner, err := pgxpool.New(ctx, "postgres://keycloak:"+testEnv(t, "KC_DB_PASSWORD")+"@127.0.0.1:"+testEnv(t, "POSTGRES_HOST_PORT")+"/keycloak?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	const disabledID = "11111111-2222-4333-8444-555555555555"
	if _, err := owner.Exec(ctx, `INSERT INTO user_entity (id, realm_id, username, enabled, created_timestamp, not_before, email_verified)
		SELECT $1, r.id, 'kcread-disabled-probe', false, 0, 0, false FROM realm r WHERE r.name = $2 ON CONFLICT (id) DO NOTHING`, disabledID, cfg.realm); err != nil {
		t.Fatalf("seed disabled user row: %v", err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DELETE FROM user_entity WHERE id = $1`, disabledID) })
	if st, err := reader.UserEnabled(ctx, disabledID); st != KCStateFalse || err != nil {
		t.Fatalf("disabled user = %s, %v; want false", st, err)
	}
}

// TestLive_KCDBReader_ProbeAndReadFailures: the probe refuses a database without Keycloak's
// tables (identity's own), and a reader whose pool is gone answers unknown with an error.
func TestLive_KCDBReader_ProbeAndReadFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := NewKCDBReader(ctx, identityPool(t), "kiban"); err == nil {
		t.Fatal("probe against the application database must fail: no realm table there")
	}
	// A realm table without the enabled column on user_entity (a future Keycloak schema) fails
	// the second probe: scratch tables in the application database, dropped again.
	admin := adminPool(t)
	for _, stmt := range []string{
		`CREATE TABLE public.realm (id text PRIMARY KEY, name text)`,
		`CREATE TABLE public.user_entity (id text PRIMARY KEY, realm_id text)`,
		`INSERT INTO public.realm VALUES ('r1', 'probe')`,
		`GRANT SELECT ON public.realm, public.user_entity TO kiban_identity`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP TABLE public.user_entity, public.realm`) })
	if _, err := NewKCDBReader(ctx, identityPool(t), "probe"); err == nil {
		t.Fatal("a user_entity without an enabled column must fail the probe")
	}
	cfg := loadKCConfig(t)
	dsn := "postgres://kiban_kcread:" + testEnv(t, "KIBAN_IDENTITY_DB_PASSWORD") + "@127.0.0.1:" + testEnv(t, "POSTGRES_HOST_PORT") + "/keycloak?sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewKCDBReader(ctx, pool, cfg.realm)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if st, err := reader.UserEnabled(ctx, "00000000-0000-0000-0000-000000000000"); st != KCStateUnknown || err == nil {
		t.Fatalf("closed pool: %s, %v; want unknown with an error", st, err)
	}
}
