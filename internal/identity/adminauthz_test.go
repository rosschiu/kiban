// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/obs"
)

func TestEngineAdminAuthorizer_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer good" {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
	}))
	defer srv.Close()

	authz := NewEngineAdminAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer good"}, "identity.mfa_policy.set_global")
	if !ok || err != nil {
		t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
	}
}

func TestEngineAdminAuthorizer_EmptyBearer_FailsClosed(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	authz := NewEngineAdminAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{}, "identity.mfa_policy.set_global")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
	if called {
		t.Fatal("server must not be called for an empty bearer")
	}
}

// A confirmed denial (one of authz's global-scope denial reasons) is a *DeniedError carrying the
// reason; the request's correlation id is forwarded to authz.
func TestEngineAdminAuthorizer_Denied_IsDeniedError(t *testing.T) {
	var gotCorrelation string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCorrelation = r.Header.Get("x-correlation-id")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": "PLATFORM_ROLE_REQUIRED"}})
	}))
	defer srv.Close()

	authz := NewEngineAdminAuthorizer(srv.URL, srv.Client())
	ctx := obs.ContextWithCorrelation(t.Context(), "corr-deny")
	ok, err := authz.Can(ctx, AuthContext{RawBearer: "Bearer member"}, "identity.mfa_policy.set_global")
	var denied *DeniedError
	if ok || !errors.As(err, &denied) || denied.Reason != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("got (%v, %v), want (false, *DeniedError{PLATFORM_ROLE_REQUIRED})", ok, err)
	}
	if gotCorrelation != "corr-deny" {
		t.Errorf("x-correlation-id forwarded = %q, want corr-deny", gotCorrelation)
	}
}

// A denial with a reason this package does not recognize as a confirmed denial stays uncertain.
func TestEngineAdminAuthorizer_UnknownDenialReason_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": "SOMETHING_NEW"}})
	}))
	defer srv.Close()

	authz := NewEngineAdminAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer member"}, "identity.mfa_policy.set_global")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestEngineAdminAuthorizer_Unreachable_FailsClosed(t *testing.T) {
	authz := NewEngineAdminAuthorizer("http://127.0.0.1:1", &http.Client{})
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer good"}, "identity.mfa_policy.set_global")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}
