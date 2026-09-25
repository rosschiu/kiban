// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"

	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/registry"
)

// VerifyStep re-reads everything the earlier steps seeded and reports drift found-and-not-
// overwritten — runtime-owned state is sacred. It is deliberately read-only: it never writes,
// so it is always Converged on success — a discrepancy it finds is reported as a Failed
// outcome with the diff, never silently repaired (repairing would be this step secretly
// becoming a second writer of runtime-owned state).
type VerifyStep struct{}

func (VerifyStep) Name() string { return "verify" }

func (VerifyStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	var details []string

	if deps.Pool != nil {
		count, err := store.CountSuperadmins(ctx, deps.Pool)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("verify: re-count superadmins: %w", err)
		}
		if count < 1 {
			return OutcomeFailed, "", fmt.Errorf("verify: no superadmin exists after bootstrap (expected >=1, found %d)", count)
		}
		details = append(details, fmt.Sprintf("platform role: %d superadmin(s) present", count))
	} else {
		details = append(details, "platform role: skipped (Pool not set)")
	}

	if deps.RegistryPool != nil {
		installed, err := countModuleInstallationRows(ctx, deps.RegistryPool, KnownModules)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("verify: re-count registry installation rows: %w", err)
		}
		// Never asserts installed == len(KnownModules): an operator may have disabled/enabled a
		// module since the last bootstrap run, and that runtime-owned state is exactly what
		// Verify must NOT treat as drift — this only re-reads and reports the count.
		details = append(details, fmt.Sprintf("registry: %d/%d known module row(s) present", installed, len(KnownModules)))
		if _, err := registry.NewStore(deps.RegistryPool).Catalog(ctx); err != nil {
			return OutcomeFailed, "", fmt.Errorf("verify: re-read registry catalog: %w", err)
		}
	} else {
		details = append(details, "registry: skipped (RegistryPool not set)")
	}

	if deps.AuthzPool != nil {
		allPresent, err := tuplesExist(ctx, deps.AuthzPool, StructuralTuples)
		if err != nil {
			return OutcomeFailed, "", fmt.Errorf("verify: re-check structural tuples: %w", err)
		}
		if !allPresent {
			return OutcomeFailed, "", fmt.Errorf("verify: a previously-seeded structural tuple is missing (drift) — bootstrap never repairs runtime-owned/relationship state, stopping instead of overwriting")
		}
		details = append(details, fmt.Sprintf("authz: %d structural tuple(s) confirmed present", len(StructuralTuples)))
	} else {
		details = append(details, "authz: skipped (AuthzPool not set)")
	}

	return OutcomeConverged, joinDetails(details), nil
}
