// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// This file backfills clients.go's remaining branches: each real client's non-2xx/decode-error/transport-error
// paths that decision_test.go/company_scope_test.go/clients_test.go's happy-path-oriented tests
// don't reach.

// jsonServer serves a fixed status + body for every request, for exercising a client's non-2xx
// and malformed-JSON branches.
func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func closedServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	return srv
}

func TestIdentityClientErrorBranches(t *testing.T) {
	t.Run("Enabled: non-200 status is an error, not a state", func(t *testing.T) {
		srv := jsonServer(t, http.StatusInternalServerError, `{}`)
		c := NewIdentityClient(&http.Client{Timeout: time.Second}, srv.URL)
		state, err := c.Enabled(context.Background(), "u1")
		if err == nil {
			t.Fatalf("want error, got state=%v", state)
		}
	})

	t.Run("Enabled: 404 (not found) is KCUnknown, no error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusNotFound, ``)
		c := NewIdentityClient(&http.Client{Timeout: time.Second}, srv.URL)
		state, err := c.Enabled(context.Background(), "u1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state != decision.KCUnknown {
			t.Fatalf("state = %v, want KCUnknown", state)
		}
	})

	t.Run("Enabled: malformed JSON body is a decode error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `{not json`)
		c := NewIdentityClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.Enabled(context.Background(), "u1")
		if err == nil {
			t.Fatal("want decode error, got nil")
		}
	})

	t.Run("Enabled: unrecognized kcEnabled string is KCUnknown", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `{"data":{"lifecycle":"active","kcEnabled":"maybe"}}`)
		c := NewIdentityClient(&http.Client{Timeout: time.Second}, srv.URL)
		state, err := c.Enabled(context.Background(), "u1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state != decision.KCUnknown {
			t.Fatalf("state = %v, want KCUnknown", state)
		}
	})

	t.Run("Enabled: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewIdentityClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.Enabled(context.Background(), "u1")
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})

	t.Run("Lookup: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewIdentityClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.Lookup(context.Background(), "u1")
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})
}

func TestRegistryClientErrorBranches(t *testing.T) {
	t.Run("Enabled: non-200/404 status is an error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusInternalServerError, `{}`)
		c := NewRegistryClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.Enabled(context.Background(), "mod")
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("Enabled: 404 means not enabled, no error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusNotFound, ``)
		c := NewRegistryClient(&http.Client{Timeout: time.Second}, srv.URL)
		enabled, err := c.Enabled(context.Background(), "mod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if enabled {
			t.Fatal("want enabled=false for an unknown module")
		}
	})

	t.Run("Enabled: malformed JSON body is a decode error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `{bad`)
		c := NewRegistryClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.Enabled(context.Background(), "mod")
		if err == nil {
			t.Fatal("want decode error, got nil")
		}
	})

	t.Run("Enabled: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewRegistryClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.Enabled(context.Background(), "mod")
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})

	t.Run("KnownEnabled: non-200 status is an error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusInternalServerError, `{}`)
		c := NewRegistryClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.KnownEnabled(context.Background())
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("KnownEnabled: malformed JSON body is a decode error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `[[[`)
		c := NewRegistryClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.KnownEnabled(context.Background())
		if err == nil {
			t.Fatal("want decode error, got nil")
		}
	})

	t.Run("KnownEnabled: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewRegistryClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.KnownEnabled(context.Background())
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})
}

func TestOrgClientErrorBranches(t *testing.T) {
	t.Run("State: non-200 status is an error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusInternalServerError, `{}`)
		c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.State(context.Background(), "co-1")
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("State: malformed JSON body is a decode error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `{`)
		c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.State(context.Background(), "co-1")
		if err == nil {
			t.Fatal("want decode error, got nil")
		}
	})

	t.Run("State: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewOrgClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.State(context.Background(), "co-1")
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})

	t.Run("Membership: non-200 status is an error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusInternalServerError, `{}`)
		c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.Membership(context.Background(), "co-1", "u1")
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("Membership: malformed JSON body is a decode error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `not json`)
		c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)
		_, err := c.Membership(context.Background(), "co-1", "u1")
		if err == nil {
			t.Fatal("want decode error, got nil")
		}
	})

	t.Run("Membership: not a member (isMember=false) is a plain result, not an error", func(t *testing.T) {
		srv := jsonServer(t, http.StatusOK, `{"data":{"isMember":false}}`)
		c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)
		ms, err := c.Membership(context.Background(), "co-1", "u1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ms.IsMember {
			t.Fatal("want IsMember=false")
		}
	})

	t.Run("Membership: transport error", func(t *testing.T) {
		srv := closedServer(t)
		c := NewOrgClient(&http.Client{Timeout: 300 * time.Millisecond}, srv.URL)
		_, err := c.Membership(context.Background(), "co-1", "u1")
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})
}

// TestOrgClientEscapesPathSegments proves decision-dependency URLs cannot be rewritten by a
// request-body value: a companyId containing "/" and "?" reaches org as
// ONE path segment of the company-state route, never a different endpoint or a query string.
func TestOrgClientEscapesPathSegments(t *testing.T) {
	const hostile = "x/state?y=1#z"
	var gotCompany, gotSub, gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/org/companies/{companyID}/state", func(w http.ResponseWriter, r *http.Request) {
		gotCompany, gotQuery = r.PathValue("companyID"), r.URL.RawQuery
		writeTestData(w, map[string]bool{"exists": true, "isActive": true})
	})
	mux.HandleFunc("GET /internal/org/companies/{companyID}/members/by-kcsub/{kcSub}", func(w http.ResponseWriter, r *http.Request) {
		gotCompany, gotSub, gotQuery = r.PathValue("companyID"), r.PathValue("kcSub"), r.URL.RawQuery
		writeTestData(w, map[string]any{"isMember": true, "isActive": true})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewOrgClient(&http.Client{Timeout: time.Second}, srv.URL)

	st, err := c.State(context.Background(), hostile)
	if err != nil || !st.Exists {
		t.Fatalf("State: err=%v state=%+v — the hostile id must still hit the state route", err, st)
	}
	if gotCompany != hostile || gotQuery != "" {
		t.Fatalf("State: org saw companyID=%q query=%q, want the literal id and no query", gotCompany, gotQuery)
	}
	ms, err := c.Membership(context.Background(), hostile, "u/1?x")
	if err != nil || !ms.IsMember {
		t.Fatalf("Membership: err=%v state=%+v", err, ms)
	}
	if gotCompany != hostile || gotSub != "u/1?x" || gotQuery != "" {
		t.Fatalf("Membership: org saw companyID=%q kcSub=%q query=%q", gotCompany, gotSub, gotQuery)
	}
}
