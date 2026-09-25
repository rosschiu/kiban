// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// freshPostgres starts an ephemeral, disposable Postgres 18 container (a genuinely fresh
// CLUSTER — not merely a fresh database on the already-migrated dev cluster, whose four
// per-service roles already exist and would collide with migrations/registry/0001_roles.sql's
// unconditional CREATE ROLE) on a random host port, waits for it to accept connections, and
// registers cleanup. A plain `docker run` is used because the clean-deploy-from-migrations
// claim is about a fresh CLUSTER, matching what `make dev-clean && make dev` actually produces
// (a fresh Postgres volume).
//
// freshPostgresPassword is the fixed password freshPostgres gives the superuser and the two
// initdb roles (infra/postgres-init, bind-mounted so the fresh cluster is shaped exactly like
// `make dev`'s: migrations then run as the non-superuser owner kiban) — fine for a
// throwaway, 127.0.0.1-only, immediately-`docker rm -f`'d container.
const freshPostgresPassword = "fresh-test-password"

func freshPostgres(t *testing.T) (host string, port string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("dbtest: docker not available, skipping fresh-cluster migrations proof")
	}

	containerName := fmt.Sprintf("kiban-bootstrap-fresh-%d", time.Now().UnixNano())
	freePort, err := freeTCPPort()
	if err != nil {
		t.Fatalf("dbtest: find free port: %v", err)
	}

	runCmd := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_USER=postgres",
		"-e", "POSTGRES_PASSWORD="+freshPostgresPassword,
		"-e", "POSTGRES_DB=kiban",
		"-e", "KC_DB_PASSWORD="+freshPostgresPassword,
		"-e", "KIBAN_DB_PASSWORD="+freshPostgresPassword,
		"-v", bootstrapRepoRoot(t)+"/infra/postgres-init:/docker-entrypoint-initdb.d:ro",
		"-p", fmt.Sprintf("127.0.0.1:%s:5432", freePort),
		"postgres:18-alpine",
	)
	var out strings.Builder
	runCmd.Stdout = &out
	runCmd.Stderr = &out
	if err := runCmd.Run(); err != nil {
		t.Fatalf("dbtest: docker run postgres: %v (output: %s)", err, out.String())
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	waitForPostgresReady(t, "127.0.0.1", freePort, "kiban", freshPostgresPassword, "kiban")
	return "127.0.0.1", freePort
}

func freeTCPPort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}

func waitForPostgresReady(t *testing.T, host, port, user, password, db string) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, db)
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(context.Background(), dsn)
		if err == nil {
			pingErr := pool.Ping(context.Background())
			pool.Close()
			if pingErr == nil {
				return
			}
			lastErr = pingErr
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("dbtest: fresh postgres never became ready: %v", lastErr)
}

// TestMigrate_FreshDatabase_AppliesAllServicesInDependencyOrder proves tern migrations for
// registry, identity, org, and authz all apply cleanly, in that order, against a brand-new
// Postgres cluster (clean deploy from migrations alone), MigrationsStep reports OutcomeApplied
// (real DDL happened), and the grant-matrix spot-check passes.
func TestMigrate_FreshDatabase_AppliesAllServicesInDependencyOrder(t *testing.T) {
	host, port := freshPostgres(t)
	password := freshPostgresPassword

	deps := &Deps{
		RepoRoot:       bootstrapRepoRoot(t),
		MigrationsRoot: bootstrapRepoRoot(t) + "/migrations",
		DBEnv: map[string]string{
			"KIBAN_DB_HOST":     host,
			"KIBAN_DB_PORT":     port,
			"POSTGRES_DB":       "kiban",
			"KIBAN_DB_PASSWORD": password,
		},
		RolePasswords: map[string]string{
			"registry": "fresh-registry-pw",
			"identity": "fresh-identity-pw",
			"org":      "fresh-org-pw",
			"authz":    "fresh-authz-pw",
		},
		SetRolePasswordsScript: bootstrapRepoRoot(t) + "/migrations/registry/set-role-passwords.sh",
	}

	ownerDSN := fmt.Sprintf("postgres://kiban:%s@%s:%s/kiban?sslmode=disable", password, host, port)
	ownerPool, err := pgxpool.New(context.Background(), ownerDSN)
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	defer ownerPool.Close()
	deps.Pool = ownerPool

	step := MigrationsStep{}
	outcome, detail, err := step.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("migrations step failed: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("outcome = %s, want applied (a fresh database must apply real migrations)", outcome)
	}
	t.Logf("migrations detail: %s", detail)

	for _, service := range MigrationServiceOrder {
		version, err := schemaVersion(context.Background(), ownerPool, service)
		if err != nil {
			t.Fatalf("%s: read final schema version: %v", service, err)
		}
		if version <= 0 {
			t.Errorf("%s: schema version = %d, want > 0 after migrations applied", service, version)
		}
	}

	// Re-run against the SAME now-migrated fresh cluster: every service must converge (no new
	// DDL), proving idempotence — the other half of "applied|converged|failed truthfully".
	outcome2, detail2, err := step.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("second migrations run failed: %v (detail: %s)", err, detail2)
	}
	if outcome2 != OutcomeConverged {
		t.Fatalf("second run outcome = %s, want converged (re-running migrations against an already-migrated db must be a no-op)", outcome2)
	}
}
