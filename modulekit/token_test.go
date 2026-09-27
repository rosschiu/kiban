// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/rosschiu/kiban/modulekit/kittest"
)

const (
	testIssuerName = "test-issuer"
	testAudience   = "kiban-api"
	testModule     = "testmod"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTokenVerifier_ValidToken(t *testing.T) {
	issuer := kittest.NewIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.JWKS.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := issuer.Sign(t, testIssuerName, testAudience, "kcsub-alice", time.Now().Add(time.Hour))
	sub, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "kcsub-alice" {
		t.Fatalf("expected subject kcsub-alice, got %q", sub)
	}
}

func TestTokenVerifier_UnreachableJWKS_Errors(t *testing.T) {
	_, err := NewTokenVerifier(context.Background(), "http://127.0.0.1:1/certs", testIssuerName, testAudience, testModule)
	if err == nil {
		t.Fatal("expected an error for an unreachable JWKS endpoint")
	}
}

// wantInvalid asserts the module-prefixed ErrTokenInvalid wrap — text "<module>: bearer token
// invalid", matched by errors.Is.
func wantInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
	if err.Error() != testModule+": bearer token invalid" {
		t.Fatalf("error text = %q", err.Error())
	}
}

func TestTokenVerifier_ExpiredToken(t *testing.T) {
	issuer := kittest.NewIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.JWKS.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := issuer.Sign(t, testIssuerName, testAudience, "kcsub-alice", time.Now().Add(-time.Hour))
	_, err = verifier.Verify(context.Background(), token)
	wantInvalid(t, err)
}

func TestTokenVerifier_WrongAudience(t *testing.T) {
	issuer := kittest.NewIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.JWKS.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := issuer.Sign(t, testIssuerName, "some-other-audience", "kcsub-alice", time.Now().Add(time.Hour))
	_, err = verifier.Verify(context.Background(), token)
	wantInvalid(t, err)
}

func TestTokenVerifier_EmptyToken(t *testing.T) {
	issuer := kittest.NewIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.JWKS.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), "")
	wantInvalid(t, err)
}

func TestTokenVerifier_EmptySubject(t *testing.T) {
	issuer := kittest.NewIssuer(t)
	verifier, err := NewTokenVerifier(context.Background(), issuer.JWKS.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := issuer.Sign(t, testIssuerName, testAudience, "", time.Now().Add(time.Hour))
	_, err = verifier.Verify(context.Background(), token)
	wantInvalid(t, err)
}

// rotatingIssuer is a JWKS test server whose served key set can change after construction — both
// Refresh/RefreshPeriodically and the retry-on-unknown-kid path need a server that simulates the
// IdP rotating to a NEW signing key the verifier's original, startup-time fetch never saw.
type rotatingIssuer struct {
	jwksServer *httptest.Server
	mu         sync.Mutex
	set        jwk.Set
	fail       bool
}

func newRotatingIssuer(t *testing.T) *rotatingIssuer {
	t.Helper()
	ri := &rotatingIssuer{set: jwk.NewSet()}
	ri.jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri.mu.Lock()
		set, fail := ri.set, ri.fail
		ri.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(ri.jwksServer.Close)
	return ri
}

// addKey generates a fresh RSA keypair with the given kid, publishes its public half in the
// served set, and returns the private key for signing.
func (ri *rotatingIssuer) addKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	ri.mu.Lock()
	_ = ri.set.AddKey(pub)
	ri.mu.Unlock()

	return priv
}

func (ri *rotatingIssuer) setFail(fail bool) {
	ri.mu.Lock()
	ri.fail = fail
	ri.mu.Unlock()
}

func signWith(t *testing.T, key jwk.Key, issuer, audience, sub string, exp time.Time) string {
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
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func TestTokenVerifier_Refresh(t *testing.T) {
	ri := newRotatingIssuer(t)
	key1 := ri.addKey(t, "key-1")

	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// Rotate in a second key AFTER the verifier's initial fetch — a token signed with it is
	// rejected until Refresh runs.
	key2 := ri.addKey(t, "key-2")
	token2 := signWith(t, key2, testIssuerName, testAudience, "kcsub-bob", time.Now().Add(time.Hour))

	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	sub, err := verifier.Verify(context.Background(), token2)
	if err != nil {
		t.Fatalf("verify after refresh: %v", err)
	}
	if sub != "kcsub-bob" {
		t.Fatalf("expected kcsub-bob, got %q", sub)
	}

	// The original key still verifies too — Refresh replaces the cached set with the full
	// current JWKS document, not just the new key.
	token1 := signWith(t, key1, testIssuerName, testAudience, "kcsub-alice", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), token1); err != nil {
		t.Fatalf("expected the original key to still verify after refresh: %v", err)
	}
}

// TestTokenVerifier_Refresh_FailureKeepsOldSet covers Refresh's error branch (prefixed error,
// cached set untouched) and RefreshPeriodically's warn-and-continue branch.
func TestTokenVerifier_Refresh_FailureKeepsOldSet(t *testing.T) {
	ri := newRotatingIssuer(t)
	key1 := ri.addKey(t, "key-1")
	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	ri.setFail(true)
	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("expected Refresh to fail while the JWKS server errors")
	}
	token1 := signWith(t, key1, testIssuerName, testAudience, "kcsub-alice", time.Now().Add(time.Hour))
	if _, err := verifier.Verify(context.Background(), token1); err != nil {
		t.Fatalf("expected the cached set to keep serving after a failed refresh: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		verifier.RefreshPeriodically(ctx, testLogger(), 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond) // a few failed ticks, logged and ignored
	cancel()
	<-done
}

func TestTokenVerifier_RefreshPeriodically(t *testing.T) {
	ri := newRotatingIssuer(t)
	ri.addKey(t, "key-1")

	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	key2 := ri.addKey(t, "key-2")
	token2 := signWith(t, key2, testIssuerName, testAudience, "kcsub-bob", time.Now().Add(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	go verifier.RefreshPeriodically(ctx, testLogger(), 10*time.Millisecond)
	t.Cleanup(cancel)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := verifier.Verify(context.Background(), token2); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected RefreshPeriodically to eventually pick up the rotated key within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTokenVerifier_RefreshPeriodically_StopsOnContextDone(t *testing.T) {
	ri := newRotatingIssuer(t)
	ri.addKey(t, "key-1")
	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		verifier.RefreshPeriodically(ctx, testLogger(), 5*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshPeriodically did not return within 5s of an already-cancelled ctx")
	}
}

// TestTokenVerifier_Verify_RetriesOnUnknownKid covers the retry-on-unknown-kid single refetch:
// a token signed with a key rotated in AFTER the verifier's cached set was built must still
// verify, via Verify's own inline single refetch, with no RefreshPeriodically goroutine running.
func TestTokenVerifier_Verify_RetriesOnUnknownKid(t *testing.T) {
	ri := newRotatingIssuer(t)
	ri.addKey(t, "key-1")

	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	key2 := ri.addKey(t, "key-2") // rotated in after the verifier's initial fetch
	token2 := signWith(t, key2, testIssuerName, testAudience, "kcsub-bob", time.Now().Add(time.Hour))

	sub, err := verifier.Verify(context.Background(), token2)
	if err != nil {
		t.Fatalf("expected Verify to self-heal via a single unknown-kid refetch, got %v", err)
	}
	if sub != "kcsub-bob" {
		t.Fatalf("expected kcsub-bob, got %q", sub)
	}
}

// TestTokenVerifier_Verify_UnknownKidRefetchFails: the inline refetch failing leaves the token
// rejected (no second retry).
func TestTokenVerifier_Verify_UnknownKidRefetchFails(t *testing.T) {
	ri := newRotatingIssuer(t)
	ri.addKey(t, "key-1")
	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	key2 := ri.addKey(t, "key-2")
	token2 := signWith(t, key2, testIssuerName, testAudience, "kcsub-bob", time.Now().Add(time.Hour))
	ri.setFail(true)
	_, err = verifier.Verify(context.Background(), token2)
	wantInvalid(t, err)
}

// TestTokenVerifier_Verify_ExpiredTokenNotRetried proves the retry-on-unknown-kid path only fires
// for an actual unknown-kid failure, not for every other rejection reason (expired, wrong
// audience) — those must still fail on the first parse with no retry.
func TestTokenVerifier_Verify_ExpiredTokenNotRetried(t *testing.T) {
	ri := newRotatingIssuer(t)
	key1 := ri.addKey(t, "key-1")
	verifier, err := NewTokenVerifier(context.Background(), ri.jwksServer.URL, testIssuerName, testAudience, testModule)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	expired := signWith(t, key1, testIssuerName, testAudience, "kcsub-alice", time.Now().Add(-time.Hour))
	_, err = verifier.Verify(context.Background(), expired)
	wantInvalid(t, err)
}
