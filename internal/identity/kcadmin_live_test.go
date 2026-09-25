// SPDX-License-Identifier: Apache-2.0

//go:build live

package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GetUserAttribute's own unit proofs (fake Keycloak admin API, no live stack needed) — tagged
// live only because the function itself is.

func TestAdminClientGetUserAttribute_UnsetReturnsEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-noattrs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "kc-sub-noattrs"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	value, err := c.GetUserAttribute(t.Context(), "kc-sub-noattrs", "kiban_mfa_required")
	if err != nil {
		t.Fatalf("get user attribute: %v", err)
	}
	if value != "" {
		t.Fatalf("expected an empty string for an unset attribute, got %q", value)
	}
}

// TestAdminClientGetUserAttribute_WrongAttributeType covers GetUserAttribute's
// "attrs[key] present but not a []any" branch (Keycloak's admin API is untyped from this
// package's point of view — getUser deliberately returns map[string]any, so a malformed/
// unexpected shape must degrade to "" rather than panic).
func TestAdminClientGetUserAttribute_WrongAttributeType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-wrongtype", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "kc-sub-wrongtype",
			"attributes": map[string]any{"kiban_mfa_required": "not-an-array"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	value, err := c.GetUserAttribute(t.Context(), "kc-sub-wrongtype", "kiban_mfa_required")
	if err != nil {
		t.Fatalf("get user attribute: %v", err)
	}
	if value != "" {
		t.Fatalf("expected an empty string for a malformed attribute value, got %q", value)
	}
}

func TestAdminClientGetUserAttribute_GetUserErrorWrapped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.GetUserAttribute(t.Context(), "kc-sub-404", "k"); err == nil {
		t.Fatal("expected an error when the underlying getUser call 404s")
	}
}
