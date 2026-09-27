// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Non-live unit tests for kcMasterClient (internal/bootstrap/kcmaster.go) against a fake
// Keycloak admin API (httptest.Server) — mocking the external Keycloak reaches the error/edge
// branches that idempotent reconciliation on a long-lived, already-converged stack never
// re-executes (create/update bodies short-circuit once converged). Every method gets both a
// success and at least one error-path case.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newFakeKC starts a fake Keycloak admin API: the master-realm token endpoint always succeeds
// (a fixed bearer token), and every other request is dispatched to handler. Returns the
// kcMasterClient wired to it and the server for the test to close.
func newFakeKC(t *testing.T, handler http.HandlerFunc) (*kcMasterClient, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-token"})
	})
	mux.HandleFunc("/", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	kc := newKCMasterClient(srv.Client(), srv.URL, "kiban", "admin", "admin")
	return kc, srv
}

func TestKCMasterClient_Token(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		})
		tok, err := kc.token(context.Background())
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if tok != "fake-token" {
			t.Errorf("token = %q, want %q", tok, "fake-token")
		}
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("bad credentials"))
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		kc := newKCMasterClient(srv.Client(), srv.URL, "kiban", "admin", "wrong")

		if _, err := kc.token(context.Background()); err == nil {
			t.Fatal("expected an error for HTTP 401")
		}
	})

	t.Run("malformed JSON response is a decode error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		kc := newKCMasterClient(srv.Client(), srv.URL, "kiban", "admin", "admin")

		if _, err := kc.token(context.Background()); err == nil {
			t.Fatal("expected a decode error")
		}
	})

	t.Run("empty access_token in an otherwise-valid response is an error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{})
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		kc := newKCMasterClient(srv.Client(), srv.URL, "kiban", "admin", "admin")

		if _, err := kc.token(context.Background()); err == nil {
			t.Fatal("expected an error for an empty access_token")
		}
	})

	t.Run("unreachable token endpoint is a request error", func(t *testing.T) {
		kc := newKCMasterClient(http.DefaultClient, "http://127.0.0.1:1", "kiban", "admin", "admin")
		if _, err := kc.token(context.Background()); err == nil {
			t.Fatal("expected an error dialing a reserved unreachable port")
		}
	})
}

func TestKCMasterClient_Do(t *testing.T) {
	t.Run("non-2xx status is an error carrying the body", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		})
		_, err := kc.do(context.Background(), http.MethodGet, "/clients/nope", nil, nil)
		if err == nil {
			t.Fatal("expected an error for HTTP 404")
		}
	})

	t.Run("malformed JSON response body is a decode error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		var out map[string]any
		_, err := kc.do(context.Background(), http.MethodGet, "/clients/x", nil, &out)
		if err == nil {
			t.Fatal("expected a decode error")
		}
	})

	t.Run("a token-fetch failure surfaces before any request is issued", func(t *testing.T) {
		kc := newKCMasterClient(http.DefaultClient, "http://127.0.0.1:1", "kiban", "admin", "admin")
		_, err := kc.do(context.Background(), http.MethodGet, "/clients", nil, nil)
		if err == nil {
			t.Fatal("expected an error (token fetch fails against an unreachable base URL)")
		}
	})
}

func TestLocationIDFrom(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://kc/admin/realms/kiban/clients/abc-123", "abc-123"},
		{"http://kc/admin/realms/kiban/clients/abc-123/", "abc-123"},
		{"", ""},
		{"no-slash-at-all", ""},
	}
	for _, c := range cases {
		if got := locationIDFrom(c.in); got != c.want {
			t.Errorf("locationIDFrom(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestKCMasterClient_DoCreate(t *testing.T) {
	t.Run("201 with a Location header returns the trailing id", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			w.Header().Set("Location", "http://kc/admin/realms/kiban/clients/new-id-1")
			w.WriteHeader(http.StatusCreated)
		})
		id, err := kc.doCreate(context.Background(), "/clients", kcClientRep{ClientID: "x"})
		if err != nil {
			t.Fatalf("doCreate: %v", err)
		}
		if id != "new-id-1" {
			t.Errorf("id = %q, want %q", id, "new-id-1")
		}
	})

	t.Run("201 with no Location header returns an empty id", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		})
		id, err := kc.doCreate(context.Background(), "/clients", kcClientRep{ClientID: "x"})
		if err != nil {
			t.Fatalf("doCreate: %v", err)
		}
		if id != "" {
			t.Errorf("id = %q, want empty", id)
		}
	})

	t.Run("non-2xx status is an error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errorMessage":"Client already exists"}`))
		})
		if _, err := kc.doCreate(context.Background(), "/clients", kcClientRep{ClientID: "dup"}); err == nil {
			t.Fatal("expected an error for HTTP 409")
		}
	})

	t.Run("a token-fetch failure surfaces before any request is issued", func(t *testing.T) {
		kc := newKCMasterClient(http.DefaultClient, "http://127.0.0.1:1", "kiban", "admin", "admin")
		if _, err := kc.doCreate(context.Background(), "/clients", kcClientRep{ClientID: "x"}); err == nil {
			t.Fatal("expected an error (token fetch fails against an unreachable base URL)")
		}
	})
}

func TestKCMasterClient_CreateClient(t *testing.T) {
	t.Run("Location header present: returns its id directly", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://kc/admin/realms/kiban/clients/abc")
			w.WriteHeader(http.StatusCreated)
		})
		id, err := kc.createClient(context.Background(), kcClientRep{ClientID: "kiban-api"})
		if err != nil {
			t.Fatalf("createClient: %v", err)
		}
		if id != "abc" {
			t.Errorf("id = %q, want %q", id, "abc")
		}
	})

	t.Run("no Location header: falls back to findClientByClientID", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/kiban/clients":
				w.WriteHeader(http.StatusCreated) // no Location
			case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/kiban/clients":
				_ = json.NewEncoder(w).Encode([]kcClientRep{{ID: "resolved-id", ClientID: "kiban-api"}})
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
		})
		id, err := kc.createClient(context.Background(), kcClientRep{ClientID: "kiban-api"})
		if err != nil {
			t.Fatalf("createClient: %v", err)
		}
		if id != "resolved-id" {
			t.Errorf("id = %q, want %q", id, "resolved-id")
		}
	})

	t.Run("no Location header and the fallback lookup can't find it either: an error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusCreated)
			case r.Method == http.MethodGet:
				_ = json.NewEncoder(w).Encode([]kcClientRep{})
			}
		})
		if _, err := kc.createClient(context.Background(), kcClientRep{ClientID: "kiban-api"}); err == nil {
			t.Fatal("expected an error when the created client can't be resolved")
		}
	})
}

func TestKCMasterClient_ProtocolMapperCRUD(t *testing.T) {
	t.Run("createProtocolMapper success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			w.WriteHeader(http.StatusCreated)
		})
		if err := kc.createProtocolMapper(context.Background(), "fe-id", kcProtocolMapperRep{Name: "aud"}); err != nil {
			t.Fatalf("createProtocolMapper: %v", err)
		}
	})

	t.Run("createProtocolMapper error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})
		if err := kc.createProtocolMapper(context.Background(), "fe-id", kcProtocolMapperRep{Name: "aud"}); err == nil {
			t.Fatal("expected an error for HTTP 400")
		}
	})

	t.Run("updateProtocolMapper success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Fatalf("method = %s, want PUT", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := kc.updateProtocolMapper(context.Background(), "fe-id", "mapper-id", kcProtocolMapperRep{Name: "aud"}); err != nil {
			t.Fatalf("updateProtocolMapper: %v", err)
		}
	})

	t.Run("updateProtocolMapper error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if err := kc.updateProtocolMapper(context.Background(), "fe-id", "mapper-id", kcProtocolMapperRep{Name: "aud"}); err == nil {
			t.Fatal("expected an error for HTTP 500")
		}
	})
}

func TestKCMasterClient_UpdateRealm(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var gotBody map[string]any
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Fatalf("method = %s, want PUT", r.Method)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusNoContent)
		})
		if err := kc.updateRealm(context.Background(), map[string]any{"displayName": "Kiban"}); err != nil {
			t.Fatalf("updateRealm: %v", err)
		}
		if gotBody["displayName"] != "Kiban" {
			t.Errorf("body = %v, want displayName=Kiban", gotBody)
		}
	})

	t.Run("error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		if err := kc.updateRealm(context.Background(), map[string]any{"displayName": "Kiban"}); err == nil {
			t.Fatal("expected an error for HTTP 403")
		}
	})
}

func TestKCMasterClient_AvailableAndAddClientRoles(t *testing.T) {
	t.Run("availableClientRoles success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]kcRoleRep{{ID: "r1", Name: "manage-users"}})
		})
		roles, err := kc.availableClientRoles(context.Background(), "user-id", "client-id")
		if err != nil {
			t.Fatalf("availableClientRoles: %v", err)
		}
		if len(roles) != 1 || roles[0].Name != "manage-users" {
			t.Errorf("roles = %v, want one manage-users role", roles)
		}
	})

	t.Run("availableClientRoles error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := kc.availableClientRoles(context.Background(), "user-id", "client-id"); err == nil {
			t.Fatal("expected an error for HTTP 500")
		}
	})

	t.Run("addClientRoles with zero roles is a no-op (no request issued)", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request %s %s — addClientRoles([]) should not call the API", r.Method, r.URL.Path)
		})
		if err := kc.addClientRoles(context.Background(), "user-id", "client-id", nil); err != nil {
			t.Fatalf("addClientRoles(nil): %v", err)
		}
	})

	t.Run("addClientRoles success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		if err := kc.addClientRoles(context.Background(), "user-id", "client-id", []kcRoleRep{{ID: "r1", Name: "manage-users"}}); err != nil {
			t.Fatalf("addClientRoles: %v", err)
		}
	})

	t.Run("addClientRoles error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})
		if err := kc.addClientRoles(context.Background(), "user-id", "client-id", []kcRoleRep{{ID: "r1", Name: "manage-users"}}); err == nil {
			t.Fatal("expected an error for HTTP 400")
		}
	})
}

func TestKCMasterClient_ClientSecrets(t *testing.T) {
	t.Run("regenerateClientSecret success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "new-secret"})
		})
		secret, err := kc.regenerateClientSecret(context.Background(), "client-id")
		if err != nil {
			t.Fatalf("regenerateClientSecret: %v", err)
		}
		if secret != "new-secret" {
			t.Errorf("secret = %q, want %q", secret, "new-secret")
		}
	})

	t.Run("regenerateClientSecret error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := kc.regenerateClientSecret(context.Background(), "client-id"); err == nil {
			t.Fatal("expected an error for HTTP 500")
		}
	})

	t.Run("clientSecret success", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s, want GET", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "existing-secret"})
		})
		secret, err := kc.clientSecret(context.Background(), "client-id")
		if err != nil {
			t.Fatalf("clientSecret: %v", err)
		}
		if secret != "existing-secret" {
			t.Errorf("secret = %q, want %q", secret, "existing-secret")
		}
	})

	t.Run("clientSecret error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		if _, err := kc.clientSecret(context.Background(), "client-id"); err == nil {
			t.Fatal("expected an error for HTTP 404")
		}
	})
}

func TestKCMasterClient_FindClientByClientID_NotFound(t *testing.T) {
	kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]kcClientRep{})
	})
	_, found, err := kc.findClientByClientID(context.Background(), "nope")
	if err != nil {
		t.Fatalf("findClientByClientID: %v", err)
	}
	if found {
		t.Error("found = true, want false for an empty result set")
	}
}

func TestKCMasterClient_FindUserByUsername(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]kcUserRep{{ID: "u1", Username: "alice"}})
		})
		rep, found, err := kc.findUserByUsername(context.Background(), "alice")
		if err != nil {
			t.Fatalf("findUserByUsername: %v", err)
		}
		if !found || rep.ID != "u1" {
			t.Errorf("found = %v, rep = %+v, want found u1", found, rep)
		}
	})

	t.Run("not found", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]kcUserRep{})
		})
		_, found, err := kc.findUserByUsername(context.Background(), "nobody")
		if err != nil {
			t.Fatalf("findUserByUsername: %v", err)
		}
		if found {
			t.Error("found = true, want false")
		}
	})

	t.Run("error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, _, err := kc.findUserByUsername(context.Background(), "alice"); err == nil {
			t.Fatal("expected an error for HTTP 500")
		}
	})
}

func TestKCMasterClient_CreateUser(t *testing.T) {
	t.Run("Location header present", func(t *testing.T) {
		var gotBody kcUserRep
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Location", "http://kc/admin/realms/kiban/users/new-user-id")
			w.WriteHeader(http.StatusCreated)
		})
		id, err := kc.createUser(context.Background(), "alice", "alice@example.invalid", "temp-pw")
		if err != nil {
			t.Fatalf("createUser: %v", err)
		}
		if id != "new-user-id" {
			t.Errorf("id = %q, want %q", id, "new-user-id")
		}
		if gotBody.Username != "alice" || len(gotBody.Credentials) != 1 || !gotBody.Credentials[0].Temporary {
			t.Errorf("request body = %+v, want username=alice with one temporary credential", gotBody)
		}
		if len(gotBody.RequiredActions) != 1 || gotBody.RequiredActions[0] != "UPDATE_PASSWORD" {
			t.Errorf("requiredActions = %v, want [UPDATE_PASSWORD]", gotBody.RequiredActions)
		}
	})

	t.Run("no Location header: falls back to findUserByUsername", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusCreated)
			case r.Method == http.MethodGet:
				_ = json.NewEncoder(w).Encode([]kcUserRep{{ID: "resolved-user-id", Username: "alice"}})
			}
		})
		id, err := kc.createUser(context.Background(), "alice", "alice@example.invalid", "temp-pw")
		if err != nil {
			t.Fatalf("createUser: %v", err)
		}
		if id != "resolved-user-id" {
			t.Errorf("id = %q, want %q", id, "resolved-user-id")
		}
	})

	t.Run("no Location header and the fallback lookup can't find it either: an error", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusCreated)
			case r.Method == http.MethodGet:
				_ = json.NewEncoder(w).Encode([]kcUserRep{})
			}
		})
		if _, err := kc.createUser(context.Background(), "alice", "alice@example.invalid", "temp-pw"); err == nil {
			t.Fatal("expected an error when the created user can't be resolved")
		}
	})

	t.Run("create fails outright", func(t *testing.T) {
		kc, _ := newFakeKC(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
		})
		if _, err := kc.createUser(context.Background(), "alice", "alice@example.invalid", "temp-pw"); err == nil {
			t.Fatal("expected an error for HTTP 409")
		}
	})
}
