// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"testing"
	"time"
)

// TestTokenVerifierRefresh covers Refresh() (0% at baseline): re-fetches the JWKS from the same
// URL and swaps the verifier's key set under its mutex, without changing subsequent Verify
// behavior for a still-valid token.
func TestTokenVerifierRefresh(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	sub, err := verifier.Verify(context.Background(), issuer.sign(t, "refresh-test-sub", time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Verify after Refresh: %v", err)
	}
	if sub != "refresh-test-sub" {
		t.Fatalf("sub = %q, want refresh-test-sub", sub)
	}
}

// TestTokenVerifierRefreshUnreachable covers Refresh's own error-wrapping branch.
func TestTokenVerifierRefreshUnreachable(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	issuer.jwksServer.Close() // now unreachable
	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh against a closed JWKS server: want error, got nil")
	}
}

// TestNewTokenVerifierUnreachable covers NewTokenVerifier's own error-wrapping branch (the
// initial jwk.Fetch failing).
func TestNewTokenVerifierUnreachable(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.jwksServer.Close()
	_, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err == nil {
		t.Fatal("NewTokenVerifier against a closed JWKS server: want error, got nil")
	}
}

// TestTokenVerifierVerifyEdgeCases covers Verify's remaining branches: an empty token string
// (fails fast, before ever parsing), and a validly-signed token that simply carries no subject
// claim (fails the ok/empty-sub check after successful parse+validation).
func TestTokenVerifierVerifyEdgeCases(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	t.Run("empty token string", func(t *testing.T) {
		_, err := verifier.Verify(context.Background(), "")
		if err != ErrTokenInvalid {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})

	t.Run("wrong issuer is rejected", func(t *testing.T) {
		_, err := verifier.Verify(context.Background(), issuer.sign(t, "u1", time.Now().Add(time.Hour)))
		if err != nil {
			t.Fatalf("sanity: a normally-signed token should verify: %v", err)
		}
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		badVerifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, testIssuerName, "some-other-audience")
		if err != nil {
			t.Fatalf("NewTokenVerifier: %v", err)
		}
		_, err = badVerifier.Verify(context.Background(), issuer.sign(t, "u1", time.Now().Add(time.Hour)))
		if err != ErrTokenInvalid {
			t.Fatalf("err = %v, want ErrTokenInvalid (audience mismatch)", err)
		}
	})

	t.Run("validly-signed token with no subject claim is rejected", func(t *testing.T) {
		noSub := issuer.signNoSubject(t, time.Now().Add(time.Hour))
		_, err := verifier.Verify(context.Background(), noSub)
		if err != ErrTokenInvalid {
			t.Fatalf("err = %v, want ErrTokenInvalid (missing subject)", err)
		}
	})
}
