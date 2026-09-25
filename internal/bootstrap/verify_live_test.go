// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

// Live proof for VerifyStep. VerifyStep is read-only re-verification of
// what earlier steps seeded (identity superadmin count, registry catalog re-read, authz
// structural-tuple presence) — every sub-check is exercised in both its converged and its
// drift-detected (Failed) shape.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/store"
)

func TestVerify_AllPoolsUnset_SkipsEverythingAndConverges(t *testing.T) {
	outcome, detail, err := VerifyStep{}.Run(context.Background(), &Deps{})
	if err != nil {
		t.Fatalf("Run: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged", outcome)
	}
	for _, want := range []string{"platform role: skipped", "registry: skipped", "authz: skipped"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail = %q, want it to contain %q", detail, want)
		}
	}
}

func TestVerify_PlatformRole_ConvergesWhenASuperadminExists(t *testing.T) {
	deps := &Deps{Pool: bootstrapAdminPool(t)}

	// This dev stack's own bootstrap run always seeds exactly one superadmin — VerifyStep's own
	// re-count must see it (>= 1), never a hard-coded "there must be a fresh one this test made".
	outcome, detail, err := VerifyStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("Run: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged: %s", outcome, detail)
	}
	if !strings.Contains(detail, "superadmin(s) present") {
		t.Errorf("detail = %q, want it to report the superadmin count", detail)
	}
}

func TestVerify_Registry_ReReadsCatalogAndInstallationCount(t *testing.T) {
	registryPool := bootstrapServicePool(t, "kiban_registry", bootstrapTestEnv(t, "KIBAN_REGISTRY_DB_PASSWORD"))
	deps := &Deps{RegistryPool: registryPool}

	outcome, detail, err := VerifyStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("Run: %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged: %s", outcome, detail)
	}
	if !strings.Contains(detail, "known module row(s) present") {
		t.Errorf("detail = %q, want it to report the installation-row count", detail)
	}
}

func TestVerify_Authz_StructuralTuplesPresentConvergesThenMissingFails(t *testing.T) {
	authzPool := bootstrapServicePool(t, "kiban_authz", bootstrapTestEnv(t, "KIBAN_AUTHZ_DB_PASSWORD"))
	tp := store.Tuple{
		ObjectType: "system", ObjectID: fmt.Sprintf("wp-verify-%d", time.Now().UnixNano()),
		Relation: "superadmin", SubjectType: "user", SubjectID: "wp-verify-u1",
	}
	t.Cleanup(func() {
		_, _ = authzPool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, tp.ObjectID)
		_, _ = authzPool.Exec(context.Background(), `DELETE FROM authz.grant_ledger WHERE object_id = $1`, tp.ObjectID)
	})

	origTuples := StructuralTuples
	StructuralTuples = []store.Tuple{tp}
	t.Cleanup(func() { StructuralTuples = origTuples })

	if _, _, err := SeedStructuralTuples(context.Background(), authzPool, "bootstrap-verify-test", []store.Tuple{tp}); err != nil {
		t.Fatalf("seed the structural tuple this test verifies: %v", err)
	}

	deps := &Deps{AuthzPool: authzPool}

	outcome, detail, err := VerifyStep{}.Run(context.Background(), deps)
	if err != nil {
		t.Fatalf("Run (tuple present): %v (detail: %s)", err, detail)
	}
	if outcome != OutcomeConverged {
		t.Fatalf("outcome = %s, want converged when the tuple is present: %s", outcome, detail)
	}
	if !strings.Contains(detail, "structural tuple(s) confirmed present") {
		t.Errorf("detail = %q, want it to report the confirmed tuple count", detail)
	}

	// Simulate drift: the tuple SeedStep is supposed to have seeded is gone (someone/something
	// deleted it directly). VerifyStep must FAIL loudly, never silently re-seed it (its own
	// doc comment: "bootstrap never repairs runtime-owned/relationship state").
	if _, err := authzPool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, tp.ObjectID); err != nil {
		t.Fatalf("simulate drift by deleting the tuple: %v", err)
	}

	outcome2, _, err := VerifyStep{}.Run(context.Background(), deps)
	if err == nil {
		t.Fatal("expected VerifyStep to fail when a previously-seeded structural tuple is missing")
	}
	if outcome2 != OutcomeFailed {
		t.Errorf("outcome = %s, want failed", outcome2)
	}
}
