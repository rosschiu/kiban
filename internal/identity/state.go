// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"fmt"
)

// UserState is the shape GET /internal/identity/users/{kcSub}/state returns — the effective-
// access decision's step 2/3 inputs: DB lifecycle plus a LIVE Keycloak kcEnabled
// tri-state (never defaulted to enabled).
type UserState struct {
	Lifecycle string
	KCEnabled string
}

// ResolveUserState looks up kcSub's identity.user_account row (ErrUserNotFound if absent —
// callers map that to a 404) and queries Keycloak live for the enabled flag via admin. A
// Keycloak query failure never fails the whole call: it surfaces as KCEnabled=KCStateUnknown so
// callers can feed DEPENDENCY_UNAVAILABLE instead of guessing allow.
func (s *Store) ResolveUserState(ctx context.Context, admin *AdminClient, kcSub string) (UserState, error) {
	user, err := s.GetUserByKcSub(ctx, kcSub)
	if err != nil {
		return UserState{}, fmt.Errorf("identity: resolve user state: %w", err)
	}

	kcEnabled, _ := admin.UserEnabled(ctx, kcSub) // error already collapsed into KCStateUnknown
	return UserState{Lifecycle: user.Lifecycle, KCEnabled: kcEnabled}, nil
}
