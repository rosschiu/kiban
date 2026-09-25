// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Non-live unit tests for PreflightStep's HTTP-only helpers (checkKeycloakReady/
// tryKeycloakReady, fetchRealmIssuer/tryFetchRealmIssuer) — these touch no Postgres/Keycloak
// dependency directly, just deps.HTTPClient against a local httptest.Server, so they run under
// `make check` like every other package's own unit suite.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTryKeycloakReady(t *testing.T) {
	t.Run("200 is ready", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health/ready" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		if err := tryKeycloakReady(context.Background(), srv.Client(), srv.URL); err != nil {
			t.Fatalf("tryKeycloakReady: %v", err)
		}
	})

	t.Run("non-200 is an error naming the status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		err := tryKeycloakReady(context.Background(), srv.Client(), srv.URL)
		if err == nil {
			t.Fatal("expected an error for HTTP 503")
		}
	})

	t.Run("unreachable base URL is a request error", func(t *testing.T) {
		err := tryKeycloakReady(context.Background(), http.DefaultClient, "http://127.0.0.1:1")
		if err == nil {
			t.Fatal("expected an error dialing a reserved unreachable port")
		}
	})

	t.Run("invalid URL fails building the request", func(t *testing.T) {
		err := tryKeycloakReady(context.Background(), http.DefaultClient, "http://\x7f")
		if err == nil {
			t.Fatal("expected an error building the request from a malformed base URL")
		}
	})
}

func TestCheckKeycloakReady(t *testing.T) {
	t.Run("succeeds on the first attempt", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		if err := checkKeycloakReady(context.Background(), srv.Client(), srv.URL); err != nil {
			t.Fatalf("checkKeycloakReady: %v", err)
		}
	})

	t.Run("retries through an initial failure and then succeeds", func(t *testing.T) {
		var calls int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		if err := checkKeycloakReady(context.Background(), srv.Client(), srv.URL); err != nil {
			t.Fatalf("checkKeycloakReady: %v", err)
		}
		if calls < 2 {
			t.Fatalf("expected at least 2 calls (one failure + a retry), got %d", calls)
		}
	})

	t.Run("a context that expires before the retry delay elapses returns ctx.Err()", func(t *testing.T) {
		// attempt 0 fails immediately (bad port, no sleep); attempt 1's select then races an
		// already-expired context against the real retry delay — proves the ctx.Done() branch
		// without waiting out the full un-cancelled retry budget.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		err := checkKeycloakReady(ctx, http.DefaultClient, "http://127.0.0.1:1")
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestTryFetchRealmIssuer(t *testing.T) {
	t.Run("200 with a non-empty issuer", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "http://keycloak/realms/kiban"})
		}))
		defer srv.Close()

		issuer, err := tryFetchRealmIssuer(context.Background(), srv.Client(), srv.URL)
		if err != nil {
			t.Fatalf("tryFetchRealmIssuer: %v", err)
		}
		if issuer != "http://keycloak/realms/kiban" {
			t.Errorf("issuer = %q, want the discovery document's issuer", issuer)
		}
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		if _, err := tryFetchRealmIssuer(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Fatal("expected an error for HTTP 404")
		}
	})

	t.Run("malformed JSON body is a decode error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()

		if _, err := tryFetchRealmIssuer(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Fatal("expected a JSON decode error")
		}
	})

	t.Run("empty issuer field is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": ""})
		}))
		defer srv.Close()

		if _, err := tryFetchRealmIssuer(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Fatal("expected an error for an empty issuer")
		}
	})

	t.Run("unreachable discovery URL is a request error", func(t *testing.T) {
		if _, err := tryFetchRealmIssuer(context.Background(), http.DefaultClient, "http://127.0.0.1:1"); err == nil {
			t.Fatal("expected an error dialing a reserved unreachable port")
		}
	})

	t.Run("invalid URL fails building the request", func(t *testing.T) {
		if _, err := tryFetchRealmIssuer(context.Background(), http.DefaultClient, "http://\x7f"); err == nil {
			t.Fatal("expected an error building the request from a malformed discovery URL")
		}
	})
}

func TestFetchRealmIssuer(t *testing.T) {
	t.Run("succeeds on the first attempt", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "http://keycloak/realms/kiban"})
		}))
		defer srv.Close()

		issuer, err := fetchRealmIssuer(context.Background(), srv.Client(), srv.URL)
		if err != nil {
			t.Fatalf("fetchRealmIssuer: %v", err)
		}
		if issuer == "" {
			t.Error("expected a non-empty issuer")
		}
	})

	t.Run("a context that expires before the retry delay elapses returns an error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		if _, err := fetchRealmIssuer(ctx, http.DefaultClient, "http://127.0.0.1:1"); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestPreflightStep_Name(t *testing.T) {
	if got, want := (PreflightStep{}).Name(), "preflight"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}
