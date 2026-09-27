// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/identity"
)

// SuperadminStep creates the one-time platform superadmin — ONLY if none exists yet.
// Marker = "does any `system:platform#superadmin` tuple exist" (authz/store.CountSuperadmins on
// the owner connection, deps.Pool): the tuple is the platform role's one record. A second run
// is always OutcomeConverged ("skipped"), never re-creates, re-enables, or resets the existing
// superadmin. On first run it creates the Keycloak user, then — in ONE transaction on the owner
// connection, the only role that may write both schemas — the identity user row
// (identity.SeedSuperadmin) and the tuple with its grant-ledger and audit rows (store.Grant).
type SuperadminStep struct{}

func (SuperadminStep) Name() string { return "superadmin" }

func (SuperadminStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	if deps.Pool == nil {
		return OutcomeConverged, "superadmin: skipped (Pool not set)", nil
	}

	count, err := store.CountSuperadmins(ctx, deps.Pool)
	if err != nil {
		return OutcomeFailed, "", fmt.Errorf("superadmin: count existing: %w", err)
	}
	if count > 0 {
		return OutcomeConverged, fmt.Sprintf("superadmin: already exists (n=%d) — skipped", count), nil
	}

	if deps.KeycloakAdminBaseURL == "" {
		return OutcomeFailed, "", fmt.Errorf("superadmin: no superadmin exists and KeycloakAdminBaseURL is not set — cannot create one")
	}
	if deps.SuperadminUsername == "" || deps.SuperadminPassword == "" {
		return OutcomeFailed, "", fmt.Errorf("superadmin: SuperadminUsername/SuperadminPassword required to create the one-time superadmin")
	}

	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)

	// Idempotent Keycloak-side lookup first: a prior run may have created the Keycloak user but
	// failed before reaching the grant (e.g. crashed between steps) — reuse it rather than
	// erroring on a duplicate-username conflict.
	existing, found, err := kc.findUserByUsername(ctx, deps.SuperadminUsername)
	var kcSub string
	if err != nil {
		return OutcomeFailed, "", fmt.Errorf("superadmin: look up existing Keycloak user: %w", err)
	}
	if found {
		kcSub = existing.ID
	} else {
		kcSub, err = kc.createUser(ctx, deps.SuperadminUsername, deps.SuperadminEmail, deps.SuperadminPassword)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("superadmin: create Keycloak user: %w", err)
		}
	}

	user, err := seedSuperadminRecords(ctx, deps, kcSub)
	if err != nil {
		return OutcomeFailed, "", fmt.Errorf("superadmin: seed identity record + platform role: %w", err)
	}

	return OutcomeApplied, fmt.Sprintf(
		"superadmin: created (username=%q kcSub=%q identityUserId=%q) — initial password is forced-temporary",
		deps.SuperadminUsername, kcSub, user.ID,
	), nil
}

// seedSuperadminRecords writes the identity row and the `system:platform#superadmin` tuple
// (+ ledger + audit.authz__events) for kcSub in one owner-connection transaction.
func seedSuperadminRecords(ctx context.Context, deps *Deps, kcSub string) (identity.User, error) {
	auditWriter, err := audit.NewWriter("audit.authz__events")
	if err != nil {
		return identity.User{}, fmt.Errorf("build audit writer: %w", err)
	}
	tx, err := deps.Pool.Begin(ctx)
	if err != nil {
		return identity.User{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	user, err := identity.SeedSuperadmin(ctx, tx, kcSub, deps.SuperadminEmail, deps.SuperadminUsername)
	if err != nil {
		return identity.User{}, err
	}
	if err := store.Grant(ctx, tx, "bootstrap", "one-time-superadmin", store.SuperadminTuple(kcSub)); err != nil {
		return identity.User{}, fmt.Errorf("grant platform role tuple: %w", err)
	}
	if err := auditWriter.Record(ctx, tx, audit.Event{
		Actor: "bootstrap", Action: "authz.platform_role.grant", Subject: "user:" + kcSub,
		Payload: map[string]any{"role": store.PlatformRoleSuperadmin, "grantedBy": "bootstrap", "seed": "one-time-superadmin"},
	}); err != nil {
		return identity.User{}, fmt.Errorf("audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return identity.User{}, fmt.Errorf("commit: %w", err)
	}
	return user, nil
}
