// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"testing"
)

// On a bootstrapped realm the direct-grant flow is the kiban copy carrying the
// MFA-setup authenticator as REQUIRED, bound as the realm's directGrantFlow, and a re-run of
// the reconciler is a no-op (converged).
func TestLive_DirectGrantFlow_Converged(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()
	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	changed, err := reconcileDirectGrantFlow(ctx, kc)
	if err != nil {
		t.Fatalf("reconcileDirectGrantFlow: %v (run `make dev` / `make test-stack-up` first)", err)
	}
	if changed {
		t.Fatal("reconcileDirectGrantFlow reported a change on a bootstrapped realm — not converged")
	}

	realm, err := kc.getRealm(ctx)
	if err != nil {
		t.Fatalf("get realm: %v", err)
	}
	if got, _ := realm["directGrantFlow"].(string); got != directGrantFlowAlias {
		t.Fatalf("realm directGrantFlow = %q, want %q", got, directGrantFlowAlias)
	}
	executions, err := kc.flowExecutions(ctx, directGrantFlowAlias)
	if err != nil {
		t.Fatalf("flow executions: %v", err)
	}
	mfa := findExecution(executions, mfaAuthenticatorID)
	if mfa == nil || mfa.Requirement != "REQUIRED" || mfa.Level != 0 {
		t.Fatalf("%q in %q = %+v, want a REQUIRED level-0 execution", mfaAuthenticatorID, directGrantFlowAlias, mfa)
	}
}
