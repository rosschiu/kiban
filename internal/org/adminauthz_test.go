// SPDX-License-Identifier: Apache-2.0

package org

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer good"}, "org.unit.create")
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
	ok, err := authz.Can(t.Context(), AuthContext{}, "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
	if called {
		t.Fatal("server must not be called for an empty bearer")
	}
}

// A confirmed denial (one of authz's global-scope denial reasons) is a *DeniedError carrying the
// reason; an unrecognized reason stays uncertain (fail-closed).
func TestEngineAdminAuthorizer_Denied_IsDeniedError(t *testing.T) {
	reason := "PLATFORM_ROLE_REQUIRED"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": reason}})
	}))
	defer srv.Close()

	authz := NewEngineAdminAuthorizer(srv.URL, srv.Client())
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer member"}, "org.unit.create")
	var denied *DeniedError
	if ok || !errors.As(err, &denied) || denied.Reason != reason {
		t.Fatalf("got (%v, %v), want (false, *DeniedError{PLATFORM_ROLE_REQUIRED})", ok, err)
	}

	reason = "SOMETHING_NEW"
	ok, err = authz.Can(t.Context(), AuthContext{RawBearer: "Bearer member"}, "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("unknown reason: got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestEngineAdminAuthorizer_Unreachable_FailsClosed(t *testing.T) {
	authz := NewEngineAdminAuthorizer("http://127.0.0.1:1", &http.Client{})
	ok, err := authz.Can(t.Context(), AuthContext{RawBearer: "Bearer good"}, "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}
