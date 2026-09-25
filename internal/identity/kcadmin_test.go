// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This file covers kcadmin.go's error-branch surface: token()/getUser()/
// updateUser()'s non-200 and malformed-body branches, plus SetUserAttribute's
// attribute-preservation branch (GetUserAttribute is live-tagged; see kcadmin_live_test.go). AdminClient talks to Keycloak's admin
// REST API, a genuinely external system — a fake httptest server standing in for it
// is the same pattern state_test.go's fakeKeycloak already establishes; every test here builds
// its own inline mux instead so each subtest owns its own independent per-endpoint control.

func TestAdminClientToken_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.token(t.Context()); err == nil {
		t.Fatal("expected an error for a non-200 token response")
	}
}

func TestAdminClientToken_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.token(t.Context()); err == nil {
		t.Fatal("expected an error for a malformed token response body")
	}
}

func TestAdminClientToken_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": ""})
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.token(t.Context()); err == nil {
		t.Fatal("expected an error for an empty access_token")
	}
}

func TestAdminClientUserEnabled_MalformedUserBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	state, err := c.UserEnabled(t.Context(), "kc-sub")
	if state != KCStateUnknown {
		t.Fatalf("expected KCStateUnknown for a malformed user body, got %q", state)
	}
	if err == nil {
		t.Fatal("expected a non-nil error alongside KCStateUnknown")
	}
}

func TestAdminClientUserEnabled_NoEnabledField(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "some-id"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	state, err := c.UserEnabled(t.Context(), "kc-sub")
	if state != KCStateUnknown || err == nil {
		t.Fatalf("expected KCStateUnknown+error when the response has no enabled field, got state=%q err=%v", state, err)
	}
}

func TestAdminClientUserEnabled_TokenFailurePropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	state, err := c.UserEnabled(t.Context(), "kc-sub")
	if state != KCStateUnknown || err == nil {
		t.Fatalf("expected KCStateUnknown+error on token failure, got state=%q err=%v", state, err)
	}
}

// TestAdminClientSetUserAttribute_PreservesExistingAttributes proves the GET-then-PUT round
// trip in SetUserAttribute preserves attributes it didn't touch and writes the new one.
func TestAdminClientSetUserAttribute_PreservesExistingAttributes(t *testing.T) {
	stored := map[string]any{
		"id":         "kc-sub-attr",
		"attributes": map[string]any{"other_attr": []string{"keep-me"}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-attr", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(stored)
		case http.MethodPut:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode PUT body: %v", err)
			}
			stored = body
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if err := c.SetUserAttribute(t.Context(), "kc-sub-attr", "kiban_mfa_required", "true"); err != nil {
		t.Fatalf("set user attribute: %v", err)
	}

	attrs, _ := stored["attributes"].(map[string]any)
	if got, _ := attrs["kiban_mfa_required"].([]any); len(got) != 1 || got[0] != "true" {
		t.Fatalf("expected kiban_mfa_required=[true] stored, got %v", attrs["kiban_mfa_required"])
	}

	// The pre-existing attribute this call never touched must have survived the round trip.
	if _, ok := attrs["other_attr"]; !ok {
		t.Fatalf("expected other_attr to survive the GET-then-PUT round trip, stored=%v", stored)
	}
}

func TestAdminClientUpdateUser_NonOKStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-bad-update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "kc-sub-bad-update"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if err := c.SetUserAttribute(t.Context(), "kc-sub-bad-update", "k", "v"); err == nil {
		t.Fatal("expected an error when the update-user PUT fails")
	}
}

func TestAdminClientGetUser_NonOKStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if err := c.SetUserAttribute(t.Context(), "kc-sub-404", "k", "v"); err == nil {
		t.Fatal("expected an error when the underlying getUser call 404s")
	}
}

// TestAdminClientToken_UnreachableServer covers token()'s http.Client.Do network-error branch
// (distinct from the non-200-status branch every other token() test here exercises): a
// connection actively refused, not a real server answering with a bad status.
func TestAdminClientToken_UnreachableServer(t *testing.T) {
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "realm", "client", "secret")
	if _, err := c.token(t.Context()); err == nil {
		t.Fatal("expected an error for an unreachable Keycloak")
	}
}

// TestAdminClientToken_MalformedBaseURLFailsRequestBuild covers token()'s
// http.NewRequestWithContext build-error branch: a base URL containing a raw control character
// makes the assembled token URL invalid.
func TestAdminClientToken_MalformedBaseURLFailsRequestBuild(t *testing.T) {
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://\x7f.invalid", "realm", "client", "secret")
	if _, err := c.token(t.Context()); err == nil {
		t.Fatal("expected an error for a malformed base URL")
	}
}

// TestAdminClientGetUser_TokenErrorPropagates covers getUser's own token-error branch (distinct
// from UserEnabled's: getUser is called both directly here and via SetUserAttribute/
// GetUserAttribute, but only a direct call isolates getUser's own `if err != nil { return nil,
// err }` line from those wrapper functions' own error-wrapping).
func TestAdminClientGetUser_TokenErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.getUser(t.Context(), "kc-sub"); err == nil {
		t.Fatal("expected getUser to propagate a token-fetch failure")
	}
}

// TestAdminClientUpdateUser_TokenErrorPropagates covers updateUser's own token-error branch.
func TestAdminClientUpdateUser_TokenErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if err := c.updateUser(t.Context(), "kc-sub", map[string]any{"id": "kc-sub"}); err == nil {
		t.Fatal("expected updateUser to propagate a token-fetch failure")
	}
}

// TestAdminClientUpdateUser_MarshalErrorPropagates covers updateUser's json.Marshal error
// branch: a channel value can never be marshaled to JSON. getUser itself can never produce this
// (it decodes real JSON, which can't contain a channel), so this calls updateUser directly with
// a hand-built map to reach a branch that's otherwise structurally unreachable through the public
// SetUserAttribute path.
func TestAdminClientUpdateUser_MarshalErrorPropagates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	unmarshalable := map[string]any{"bad": make(chan int)}
	if err := c.updateUser(t.Context(), "kc-sub", unmarshalable); err == nil {
		t.Fatal("expected updateUser to fail marshaling an unmarshalable user map")
	}
}

// TestAdminClientUpdateUser_UnreachableServer covers updateUser's http.Client.Do network-error
// branch: the token endpoint answers fine, but the PUT to the user endpoint hits a listener that
// accepts the connection and then closes it without responding.
func TestAdminClientUpdateUser_UnreachableServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-hijack", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if err := c.updateUser(t.Context(), "kc-sub-hijack", map[string]any{"id": "kc-sub-hijack"}); err == nil {
		t.Fatal("expected updateUser to fail when the connection is closed mid-request")
	}
}

// TestAdminClientGetUser_UnreachableServer covers getUser's own http.Client.Do network-error
// branch, via the same hijack-then-close technique as
// TestAdminClientUpdateUser_UnreachableServer.
func TestAdminClientGetUser_UnreachableServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-get-hijack", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.getUser(t.Context(), "kc-sub-get-hijack"); err == nil {
		t.Fatal("expected getUser to fail when the connection is closed mid-request")
	}
}

// TestAdminClientGetUser_MalformedBody covers getUser's own decode-error branch.
func TestAdminClientGetUser_MalformedBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/realm/protocol/openid-connect/token", okTokenHandler)
	mux.HandleFunc("/admin/realms/realm/users/kc-sub-malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "realm", "client", "secret")

	if _, err := c.getUser(t.Context(), "kc-sub-malformed"); err == nil {
		t.Fatal("expected getUser to fail decoding a malformed body")
	}
}
