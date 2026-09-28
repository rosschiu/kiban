// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// IsServiceAccount against a scripted Keycloak admin API: every branch that ends in "not a
// service account" or an error is pinned, so provisioning's person default is a decision, not
// an accident.
func TestAdminClient_IsServiceAccount(t *testing.T) {
	const sub = "sa-sub-1"
	type script struct {
		user       any // GET users/{sub}
		clients    any // GET clients?clientId=..&search=true
		clientsSt  int
		saUser     any // GET clients/c-1/service-account-user
		saUserSt   int
		tokenFails bool
	}
	run := func(t *testing.T, sc script) (bool, error) {
		t.Helper()
		mux := http.NewServeMux()
		if sc.tokenFails {
			mux.HandleFunc("/realms/kc-realm/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
		} else {
			mux.HandleFunc("/realms/kc-realm/protocol/openid-connect/token", okTokenHandler)
		}
		mux.HandleFunc("/admin/realms/kc-realm/users/"+sub, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sc.user)
		})
		mux.HandleFunc("/admin/realms/kc-realm/clients", func(w http.ResponseWriter, r *http.Request) {
			if sc.clientsSt != 0 {
				w.WriteHeader(sc.clientsSt)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if s, ok := sc.clients.(string); ok {
				_, _ = w.Write([]byte(s))
				return
			}
			_ = json.NewEncoder(w).Encode(sc.clients)
		})
		mux.HandleFunc("/admin/realms/kc-realm/clients/c-1/service-account-user", func(w http.ResponseWriter, r *http.Request) {
			if sc.saUserSt != 0 {
				w.WriteHeader(sc.saUserSt)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sc.saUser)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, srv.URL, "kc-realm", "identity-service", "secret")
		return c.IsServiceAccount(context.Background(), sub)
	}
	saUser := map[string]any{"username": "service-account-app"}
	clients := []map[string]any{{"id": "c-1", "clientId": "app"}}

	t.Run("linked service account", func(t *testing.T) {
		ok, err := run(t, script{user: saUser, clients: clients, saUser: map[string]any{"id": sub}})
		if err != nil || !ok {
			t.Fatalf("= %v, %v; want true", ok, err)
		}
	})
	t.Run("a person's username needs no client call", func(t *testing.T) {
		ok, err := run(t, script{user: map[string]any{"username": "alice"}, clientsSt: 500})
		if err != nil || ok {
			t.Fatalf("= %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("no client matches the username", func(t *testing.T) {
		ok, err := run(t, script{user: saUser, clients: []any{}})
		if err != nil || ok {
			t.Fatalf("= %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("candidate client has no service account (404) and is skipped", func(t *testing.T) {
		ok, err := run(t, script{user: saUser, clients: clients, saUserSt: http.StatusNotFound})
		if err != nil || ok {
			t.Fatalf("= %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("candidate client's service account is another user", func(t *testing.T) {
		ok, err := run(t, script{user: saUser, clients: clients, saUser: map[string]any{"id": "someone-else"}})
		if err != nil || ok {
			t.Fatalf("= %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("clients endpoint refused (missing view-clients) is an error", func(t *testing.T) {
		_, err := run(t, script{user: saUser, clientsSt: http.StatusForbidden})
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("err = %v, want unexpected status 403", err)
		}
	})
	t.Run("malformed clients body is an error", func(t *testing.T) {
		_, err := run(t, script{user: saUser, clients: "{not json"})
		if err == nil {
			t.Fatal("expected a decode error")
		}
	})
	t.Run("token failure is an error", func(t *testing.T) {
		_, err := run(t, script{user: saUser, tokenFails: true})
		if err == nil {
			t.Fatal("expected a token error")
		}
	})
	t.Run("unknown user is an error", func(t *testing.T) {
		c := NewAdminClient(&http.Client{Timeout: 2 * time.Second}, "http://127.0.0.1:1", "kc-realm", "identity-service", "secret")
		if _, err := c.IsServiceAccount(context.Background(), "nobody"); err == nil {
			t.Fatal("expected an error")
		}
	})
}
