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
	Kind      string
}

// ResolveUserState looks up kcSub's identity.user_account row (ErrUserNotFound if absent —
// callers map that to a 404) and asks source for Keycloak's enabled flag. A source failure
// never fails the whole call: it surfaces as KCEnabled=KCStateUnknown so callers can feed
// DEPENDENCY_UNAVAILABLE instead of guessing allow.
func (s *Store) ResolveUserState(ctx context.Context, source UserStateSource, kcSub string) (UserState, error) {
	user, err := s.GetUserByKcSub(ctx, kcSub)
	if err != nil {
		return UserState{}, fmt.Errorf("identity: resolve user state: %w", err)
	}

	kcEnabled, _ := source.UserEnabled(ctx, kcSub) // error already collapsed into KCStateUnknown
	return UserState{Lifecycle: user.Lifecycle, KCEnabled: kcEnabled, Kind: user.Kind}, nil
}
