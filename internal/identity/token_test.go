// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// testKeyPair builds an RSA key pair wrapped as jwk.Key (kid "test-key"), serves the public
// JWKS via httptest, and returns a signer closure for building tokens signed with the private
// key — everything token_test.go needs to exercise TokenVerifier without a live Keycloak.
type testIssuer struct {
	jwksServer *httptest.Server
	privateKey jwk.Key
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, "test-key"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add public key to set: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	return &testIssuer{jwksServer: srv, privateKey: priv}
}

func (ti *testIssuer) sign(t *testing.T, issuer, audience, sub, email, preferredUsername string, exp time.Time) string {
	t.Helper()
	builder := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		Subject(sub).
		IssuedAt(time.Now()).
		Expiration(exp)
	if email != "" {
		builder = builder.Claim("email", email)
	}
	if preferredUsername != "" {
		builder = builder.Claim("preferred_username", preferredUsername)
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), ti.privateKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func TestTokenVerifier_ValidTokenExtractsClaims(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	tok := issuer.sign(t, "test-issuer", "kiban-api", "kc-sub-abc", "a@example.com", "alice", time.Now().Add(time.Hour))
	claims, err := verifier.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != "kc-sub-abc" || claims.Email != "a@example.com" || claims.PreferredUsername != "alice" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestTokenVerifier_ExpiredTokenIsInvalid(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	tok := issuer.sign(t, "test-issuer", "kiban-api", "kc-sub-abc", "", "", time.Now().Add(-time.Hour))
	if _, err := verifier.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected an error for an expired token")
	}
}

func TestTokenVerifier_WrongAudienceIsInvalid(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	tok := issuer.sign(t, "test-issuer", "some-other-audience", "kc-sub-abc", "", "", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected an error for the wrong audience")
	}
}

func TestTokenVerifier_WrongIssuerIsInvalid(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	tok := issuer.sign(t, "someone-else", "kiban-api", "kc-sub-abc", "", "", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected an error for the wrong issuer")
	}
}

func TestTokenVerifier_EmptyBearerIsInvalid(t *testing.T) {
	issuer := newTestIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.jwksServer.URL, "test-issuer", "kiban-api")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty bearer token")
	}
}
