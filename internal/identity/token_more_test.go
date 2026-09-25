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

// This file covers TokenVerifier.Refresh: both the
// success-swaps-the-set path and the failed-refresh-keeps-serving-the-last-known-good-set path
// (its own doc comment's headline behavior — a transient JWKS blip must not take down already-
// verified tokens).

func TestTokenVerifier_Refresh_Success(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if verifier.currentSet().Len() == 0 {
		t.Fatal("expected the refreshed set to still contain the test issuer's key")
	}
}

// TestTokenVerifier_NoSubjectClaimIsInvalid covers Verify's "sub missing/empty" branch —
// distinct from token_test.go's expired/wrong-audience/wrong-issuer cases, all of which fail
// earlier at jwt.Parse's own validation.
func TestTokenVerifier_NoSubjectClaimIsInvalid(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	tok := issuer.sign(t, "test-issuer", "kiban-api", "", "", "", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected an error for a token with no sub claim")
	}
}

func TestTokenVerifier_Refresh_FailureKeepsLastKnownGoodSet(t *testing.T) {
	// A JWKS server that serves once successfully, then 500s on every subsequent call —
	// Refresh's second call must fail without clobbering the set NewTokenVerifier already
	// fetched.
	calls := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			mux.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	issuer := newTestIssuer(t)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Proxy the first call through to the real test issuer's JWKS body.
		resp, err := http.Get(issuer.jwksServer.URL)
		if err != nil {
			t.Fatalf("fetch issuer jwks: %v", err)
		}
		defer resp.Body.Close()
		var raw json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			t.Fatalf("decode issuer jwks: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	before := verifier.currentSet()
	if before.Len() == 0 {
		t.Fatal("expected the initial fetch to have keys")
	}

	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("expected the second (500) refresh to fail")
	}
	after := verifier.currentSet()
	if after.Len() != before.Len() {
		t.Fatalf("expected a failed refresh to leave the set unchanged: before.Len()=%d after.Len()=%d", before.Len(), after.Len())
	}
}
