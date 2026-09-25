// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeKeycloak builds an httptest server that serves the token endpoint and one admin user
// lookup endpoint, driven by the given handlers so each subtest can control both independently.
func fakeKeycloak(t *testing.T, tokenHandler, userHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/test-realm/protocol/openid-connect/token", tokenHandler)
	mux.HandleFunc("/admin/realms/test-realm/users/", userHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func okTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-token"})
}

func TestUserState_KCEnabledTrue(t *testing.T) {
	srv := fakeKeycloak(t, okTokenHandler, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": true})
	})
	admin := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "test-realm", "identity-service", "secret")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))
	ctx := context.Background()
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-state-1", "e@example.com", "erin"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	state, err := store.ResolveUserState(ctx, admin, "kc-sub-state-1")
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.Lifecycle != "active" || state.KCEnabled != KCStateTrue {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestUserState_KCEnabledFalse(t *testing.T) {
	srv := fakeKeycloak(t, okTokenHandler, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": false})
	})
	admin := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "test-realm", "identity-service", "secret")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))
	ctx := context.Background()
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-state-2", "f@example.com", "frank"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	state, err := store.ResolveUserState(ctx, admin, "kc-sub-state-2")
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.KCEnabled != KCStateFalse {
		t.Fatalf("expected kcEnabled=false, got %+v", state)
	}
}

// TestUserState_TimeoutIsUnknown is the headline case: a slow admin API must NEVER be
// treated as enabled — it collapses to KCStateUnknown.
func TestUserState_TimeoutIsUnknown(t *testing.T) {
	srv := fakeKeycloak(t, okTokenHandler, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": true})
	})
	admin := NewAdminClient(&http.Client{Timeout: 20 * time.Millisecond}, srv.URL, "test-realm", "identity-service", "secret")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))
	ctx := context.Background()
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-state-3", "g@example.com", "grace"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	state, err := store.ResolveUserState(ctx, admin, "kc-sub-state-3")
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.KCEnabled != KCStateUnknown {
		t.Fatalf("timeout must yield KCStateUnknown, got %q", state.KCEnabled)
	}
}

func TestUserState_ServerErrorIsUnknown(t *testing.T) {
	srv := fakeKeycloak(t, okTokenHandler, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	admin := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "test-realm", "identity-service", "secret")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))
	ctx := context.Background()
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-state-4", "h@example.com", "hank"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	state, err := store.ResolveUserState(ctx, admin, "kc-sub-state-4")
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.KCEnabled != KCStateUnknown {
		t.Fatalf("500 must yield KCStateUnknown, got %q", state.KCEnabled)
	}
}

func TestUserState_TokenFetchFailureIsUnknown(t *testing.T) {
	srv := fakeKeycloak(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("user endpoint must not be called when the token fetch fails")
	})
	admin := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "test-realm", "identity-service", "wrong-secret")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))
	ctx := context.Background()
	if _, err := store.ResolveOrCreate(ctx, "kc-sub-state-5", "i@example.com", "ivan"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	state, err := store.ResolveUserState(ctx, admin, "kc-sub-state-5")
	if err != nil {
		t.Fatalf("resolve user state: %v", err)
	}
	if state.KCEnabled != KCStateUnknown {
		t.Fatalf("token failure must yield KCStateUnknown, got %q", state.KCEnabled)
	}
}

func TestUserState_UnknownUserIsNotFound(t *testing.T) {
	admin := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "test-realm", "x", "y")

	adminPoolConn := adminPool(t)
	resetIdentityFixtures(t, adminPoolConn)
	store := NewStore(identityPool(t))

	_, err := store.ResolveUserState(context.Background(), admin, "kc-sub-does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a kc_sub with no identity.user_account row")
	}
}
