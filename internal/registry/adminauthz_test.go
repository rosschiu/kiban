// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authzclient "github.com/rosschiu/kiban/internal/authz/client"
)

// TestEffectiveAccessAuthorizer covers the adapter's fail-closed contract (security-relevant):
// every outcome except an explicit ALLOWED envelope must return
// (false, ErrAuthorizationUnavailable) — THIS package's sentinel, which the HTTP layer's 503
// mapping keys off — this is registry's own independent (defense-in-depth) confirmation of the
// superadmin guard. The shared client's full branch matrix (transport, status, body shapes) is
// proven in internal/authz/client; authz is an external service here, so a fake httptest server
// stands in.

func TestEffectiveAccessAuthorizer_EmptyBearer_DeniesWithoutCallingServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	authz := NewEffectiveAccessAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{}, "platform.module.enable")
	if ok {
		t.Errorf("ok = true, want false for an empty bearer")
	}
	if err != ErrAuthorizationUnavailable {
		t.Errorf("err = %v, want ErrAuthorizationUnavailable", err)
	}
	if called {
		t.Errorf("the fake authz server must never be called with no bearer (fail closed before any I/O)")
	}
}

func TestEffectiveAccessAuthorizer_Allowed_ReturnsTrue(t *testing.T) {
	var gotAuth, gotContentType, gotPath string
	var gotBody struct{ FeatureKey, Scope, RequiredPlatformRole, Action string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"allowed": true, "reason": "ALLOWED"},
		})
	}))
	defer srv.Close()

	authz := NewEffectiveAccessAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer test-token"}, "platform.module.enable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Errorf("ok = false, want true for an explicit ALLOWED envelope")
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want forwarded verbatim", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotPath != "/internal/authz/effective-access/can" {
		t.Errorf("path = %q, want /internal/authz/effective-access/can", gotPath)
	}
	if gotBody.FeatureKey != authzclient.AdminFeatureKey || gotBody.Scope != "global" ||
		gotBody.RequiredPlatformRole != authzclient.AdminRequiredRole || gotBody.Action != "platform.module.enable" {
		t.Errorf("request wire = %+v, want the mirrored gateway guard shape", gotBody)
	}
}

func TestEffectiveAccessAuthorizer_ExplicitDeny_ReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"allowed": false, "reason": "DENIED"},
		})
	}))
	defer srv.Close()

	authz := NewEffectiveAccessAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer x"}, "platform.module.enable")
	if ok || err != ErrAuthorizationUnavailable {
		t.Errorf("Can() = (%v, %v), want (false, ErrAuthorizationUnavailable) for an explicit deny", ok, err)
	}
}

// A confirmed denial (one of authz's global-scope denial reasons) is a *DeniedError carrying
// the reason — the 403 path; the unrecognized "DENIED" above stays the fail-closed 503.
func TestEffectiveAccessAuthorizer_ConfirmedDeny_IsDeniedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"allowed": false, "reason": "PLATFORM_ROLE_REQUIRED"},
		})
	}))
	defer srv.Close()

	authz := NewEffectiveAccessAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer x"}, "platform.module.enable")
	var denied *DeniedError
	if ok || !errors.As(err, &denied) || denied.Reason != "PLATFORM_ROLE_REQUIRED" {
		t.Errorf("Can() = (%v, %v), want (false, *DeniedError{PLATFORM_ROLE_REQUIRED})", ok, err)
	}
}

func TestEffectiveAccessAuthorizer_NonOKStatus_Denies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	authz := NewEffectiveAccessAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer x"}, "platform.module.enable")
	if ok || err != ErrAuthorizationUnavailable {
		t.Errorf("Can() = (%v, %v), want (false, ErrAuthorizationUnavailable) for a 500", ok, err)
	}
}
