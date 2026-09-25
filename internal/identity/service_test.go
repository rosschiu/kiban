// SPDX-License-Identifier: Apache-2.0

package identity

import "testing"

// TestAuthUnavailableError_Message covers authUnavailableError.Error() — a small but real
// behavior: the message is stable and non-empty, since it's what
// ErrAuthorizationUnavailable.Error() returns to any caller/log line that unwraps it.
func TestAuthUnavailableError_Message(t *testing.T) {
	msg := ErrAuthorizationUnavailable.Error()
	if msg == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestDenyAllAuthorizer_AlwaysDenies(t *testing.T) {
	authz := NewDenyAllAuthorizer()
	ok, err := authz.Can(t.Context(), AuthContext{Subject: "someone"}, "any.action")
	if ok {
		t.Fatal("expected denyAllAuthorizer to never allow")
	}
	if err != ErrAuthorizationUnavailable {
		t.Fatalf("expected ErrAuthorizationUnavailable, got %v", err)
	}
}
