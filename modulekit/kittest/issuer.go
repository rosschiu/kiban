// SPDX-License-Identifier: Apache-2.0

// Package kittest is the test JWKS issuer a module's tests use to mint bearers for
// modulekit.TokenVerifier: an RSA key pair, an httptest JWKS server and a signer.
package kittest

import (
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

// Issuer serves one public key at JWKS.URL and signs with its private half.
type Issuer struct {
	JWKS *httptest.Server
	Key  jwk.Key
}

// NewIssuer generates an RS256 key pair (kid "test-key") and starts the JWKS server; both are
// released on t.Cleanup.
func NewIssuer(t *testing.T) *Issuer {
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

	return &Issuer{JWKS: srv, Key: priv}
}

// Sign mints a signed token with the given issuer, audience, subject and expiry.
func (i *Issuer) Sign(t *testing.T, issuer, audience, sub string, exp time.Time) string {
	t.Helper()
	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		Subject(sub).
		IssuedAt(time.Now()).
		Expiration(exp).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), i.Key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}
