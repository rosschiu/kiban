// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testIssuer   = "http://kc.test/realms/kiban"
	testAudience = "kiban-api"
)

// fakeJWKSServer builds an httptest server that serves the JWKS for one RSA key, plus the
// private key + key id so tests can mint their own tokens. Every call generates a fresh key —
// tests never share signing material.
type fakeJWKSServer struct {
	*httptest.Server
	priv  *rsa.PrivateKey
	keyID string
}

func newFakeJWKSServer(t *testing.T) *fakeJWKSServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubKey, err := jwk.Import(priv.PublicKey)
	if err != nil {
		t.Fatalf("import public key: %v", err)
	}
	// Unique per server so a token signed by one server is an UNKNOWN kid to another's set
	// (the rotation tests), not merely a bad signature under a colliding kid.
	keyID := fmt.Sprintf("test-key-%d", fakeKeyCounter.Add(1))
	if err := pubKey.Set(jwk.KeyIDKey, keyID); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatalf("add key to set: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &fakeJWKSServer{Server: srv, priv: priv, keyID: keyID}
}

var fakeKeyCounter atomic.Int64

type tokenOpts struct {
	subject           string
	audience          []string
	azp               string
	issuer            string
	expired           bool
	email             string
	preferredUsername string
	// Zero means the defaults (iat = now-1m, no nbf, exp = now+1h or now-1h when expired).
	issuedAt, notBefore, expiresAt time.Time
}

func (f *fakeJWKSServer) signToken(t *testing.T, opts tokenOpts) string {
	t.Helper()

	privKey, err := jwk.Import(f.priv)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, f.keyID); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	issuer := opts.issuer
	if issuer == "" {
		issuer = testIssuer
	}
	subject := opts.subject
	if subject == "" {
		subject = "user-123"
	}
	exp := time.Now().Add(time.Hour)
	if opts.expired {
		exp = time.Now().Add(-time.Hour)
	}
	if !opts.expiresAt.IsZero() {
		exp = opts.expiresAt
	}
	iat := time.Now().Add(-time.Minute)
	if !opts.issuedAt.IsZero() {
		iat = opts.issuedAt
	}

	b := jwt.NewBuilder().
		Issuer(issuer).
		Subject(subject).
		IssuedAt(iat).
		Expiration(exp)
	if !opts.notBefore.IsZero() {
		b = b.NotBefore(opts.notBefore)
	}
	if opts.audience != nil {
		b = b.Audience(opts.audience)
	}
	if opts.azp != "" {
		b = b.Claim("azp", opts.azp)
	}
	if opts.email != "" {
		b = b.Claim("email", opts.email)
	}
	if opts.preferredUsername != "" {
		b = b.Claim("preferred_username", opts.preferredUsername)
	}

	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func newTestVerifier(t *testing.T, jwksURL string) *TokenVerifier {
	t.Helper()
	v, err := NewTokenVerifier(context.Background(), jwksURL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}
	return v
}

func TestToken_ValidBearerAccepted(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	tok := srv.signToken(t, tokenOpts{
		subject: "kc-sub-1", audience: []string{testAudience},
		email: "a@example.com", preferredUsername: "alice",
	})

	authCtx, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authCtx.Subject != "kc-sub-1" {
		t.Errorf("Subject = %q, want kc-sub-1", authCtx.Subject)
	}
	if authCtx.Email != "a@example.com" || authCtx.PreferredUsername != "alice" {
		t.Errorf("authCtx = %+v, want email/preferredUsername populated", authCtx)
	}
}

func TestToken_MissingBearerRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	_, err := v.Verify(context.Background(), "")
	if !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("err = %v, want ErrTokenMissing", err)
	}
}

func TestToken_ExpiredRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	tok := srv.signToken(t, tokenOpts{audience: []string{testAudience}, expired: true})
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestToken_WrongIssuerRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	tok := srv.signToken(t, tokenOpts{audience: []string{testAudience}, issuer: "http://evil.test/realms/other"})
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// TestToken_AudienceStrict_AZPOnlyRejected proves the strict audience check: a token whose `aud` claim does NOT
// contain the literal configured audience is rejected even when `azp` names it — azp is never
// consulted as an audience fallback.
func TestToken_AudienceStrict_AZPOnlyRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	tok := srv.signToken(t, tokenOpts{audience: []string{"some-other-client"}, azp: testAudience})
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid (azp-only must never satisfy the audience check)", err)
	}
}

func TestToken_AudienceStrict_NoAudienceClaimRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	tok := srv.signToken(t, tokenOpts{}) // no audience claim at all
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestToken_WrongSignatureRejected(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherJWK, err := jwk.Import(other)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := otherJWK.Set(jwk.KeyIDKey, srv.keyID); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).Subject("someone").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), otherJWK))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = v.Verify(context.Background(), string(signed))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// TestToken_RequireAuth_MissingBearer401 proves the HTTP-layer contract: 401 +
// WWW-Authenticate: Bearer on a missing/invalid bearer.
func TestToken_RequireAuth_MissingBearer401(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := RequireAuth(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/foo/bar", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
	if called {
		t.Error("next handler must not run when auth fails")
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error.Code != "AUTH_TOKEN_MISSING" {
		t.Errorf("error.code = %q, want AUTH_TOKEN_MISSING", body.Error.Code)
	}
}

func TestToken_RequireAuth_InvalidBearer401(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := RequireAuth(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/foo/bar", nil)
	req.Header.Set("Authorization", "Bearer garbage.not.a.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error.Code != "AUTH_TOKEN_INVALID" {
		t.Errorf("error.code = %q, want AUTH_TOKEN_INVALID", body.Error.Code)
	}
}

// TestToken_RequireAuth_ValidBearerPassesThrough proves a good bearer reaches next with the
// AuthContext attached.
func TestToken_RequireAuth_ValidBearerPassesThrough(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")
	tok := srv.signToken(t, tokenOpts{subject: "kc-sub-9", audience: []string{testAudience}})

	var gotSubject string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := AuthFromContext(r.Context())
		if !ok {
			t.Error("AuthFromContext: not found")
		}
		gotSubject = authCtx.Subject
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireAuth(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/foo/bar", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotSubject != "kc-sub-9" {
		t.Errorf("subject seen by next = %q, want kc-sub-9", gotSubject)
	}
}

// TestToken_RequireAuth_XUserHeaderRejected400 proves inbound x-user-* headers are rejected
// 400 — checked BEFORE token validation even runs (no bearer needed to prove
// the rejection fires).
func TestToken_RequireAuth_XUserHeaderRejected400(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := RequireAuth(v, nil)(next)

	for _, header := range []string{"X-User-Id", "x-user-email", "X-USER-ROLES"} {
		req := httptest.NewRequest(http.MethodGet, "/api/foo/bar", nil)
		req.Header.Set(header, "spoofed")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("header %s: status = %d, want 400", header, rec.Code)
		}
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Error.Code != "BAD_REQUEST" {
			t.Errorf("header %s: error.code = %q, want BAD_REQUEST", header, body.Error.Code)
		}
	}
	if called {
		t.Error("next handler must not run when an x-user-* header is present")
	}
}

// TestToken_RequireAuth_NoHealthExemption pins that /api/health gets no unauthenticated pass:
// nothing is mounted there, so a request for a module literally named `health` is 401 like every
// other /api/* path.
func TestToken_RequireAuth_NoHealthExemption(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireAuth(v, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("status = %d, called = %v, want 401/false (unauthenticated /api/health)", rec.Code, called)
	}
}

// TestTokenVerifier_NewFailsOnUnreachableJWKS proves "a gateway that cannot validate tokens must
// not start serving" (NewTokenVerifier's own doc comment): an unreachable JWKS URL fails
// construction outright, wrapping the underlying fetch error.
func TestTokenVerifier_NewFailsOnUnreachableJWKS(t *testing.T) {
	_, err := NewTokenVerifier(context.Background(), "http://127.0.0.1:1/certs", testIssuer, testAudience)
	if err == nil {
		t.Fatal("NewTokenVerifier: want error for an unreachable JWKS endpoint, got nil")
	}
}

// TestTokenVerifier_EnsureFresh_StaleRefetches proves ensureFresh's "stale, not in cooldown"
// branch actually re-fetches: a cache older than jwksCacheTTL with no recent failure triggers
// v.fetch, advancing fetchedAt.
func TestTokenVerifier_EnsureFresh_StaleRefetches(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	staleAt := time.Now().Add(-jwksCacheTTL - time.Minute)
	v.mu.Lock()
	v.fetchedAt = staleAt
	v.mu.Unlock()

	if err := v.ensureFresh(context.Background()); err != nil {
		t.Fatalf("ensureFresh: %v", err)
	}
	v.mu.RLock()
	got := v.fetchedAt
	v.mu.RUnlock()
	if !got.After(staleAt) {
		t.Errorf("fetchedAt = %v, want refreshed to after %v", got, staleAt)
	}
}

// TestTokenVerifier_EnsureFresh_CooldownServesStaleSet proves ensureFresh's cooldown branch:
// a stale cache plus a recent failed-fetch timestamp serves the last known-good set rather than
// hammering a down JWKS endpoint on every call — no refetch attempted (fetchedAt unchanged).
func TestTokenVerifier_EnsureFresh_CooldownServesStaleSet(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	staleAt := time.Now().Add(-jwksCacheTTL - time.Minute)
	v.mu.Lock()
	v.fetchedAt = staleAt
	v.lastFailedAt = time.Now()
	v.mu.Unlock()

	if err := v.ensureFresh(context.Background()); err != nil {
		t.Fatalf("ensureFresh: want nil (serve stale-but-known-good during cooldown), got %v", err)
	}
	v.mu.RLock()
	got := v.fetchedAt
	v.mu.RUnlock()
	if !got.Equal(staleAt) {
		t.Errorf("fetchedAt = %v, want unchanged at %v (no refetch during cooldown)", got, staleAt)
	}
}

// TestTokenVerifier_EnsureFresh_CooldownNoSetErrors proves ensureFresh's last branch: in
// cooldown with NO known-good set at all (e.g. every fetch attempt has failed since startup),
// there is nothing to serve — it errors instead of silently proceeding with a nil set.
func TestTokenVerifier_EnsureFresh_CooldownNoSetErrors(t *testing.T) {
	v := &TokenVerifier{
		jwksURL: "http://127.0.0.1:1/certs",
		issuer:  testIssuer, audience: testAudience,
		client:       &http.Client{Timeout: time.Second},
		lastFailedAt: time.Now(),
	}
	err := v.ensureFresh(context.Background())
	if err == nil {
		t.Fatal("ensureFresh: want error (cooldown, no known-good set), got nil")
	}
}

// TestTokenVerifier_Refresh_ForcesFetchRegardlessOfFreshness proves Refresh bypasses the
// cache-freshness check entirely (unlike ensureFresh) — a fresh, just-created verifier still
// re-fetches and advances fetchedAt when Refresh is called directly.
func TestTokenVerifier_Refresh_ForcesFetchRegardlessOfFreshness(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")

	v.mu.RLock()
	before := v.fetchedAt
	v.mu.RUnlock()

	time.Sleep(2 * time.Millisecond) // ensure a distinguishable, later timestamp
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	v.mu.RLock()
	after := v.fetchedAt
	v.mu.RUnlock()
	if !after.After(before) {
		t.Errorf("fetchedAt after Refresh = %v, want after %v (Refresh must always re-fetch)", after, before)
	}
}

// TestTokenVerifier_Verify_EnsureFreshFailsNoSet proves Verify's own fallback: when ensureFresh
// fails AND there is no cached set at all to fall back on, Verify returns ErrTokenInvalid
// wrapping the underlying cause, never reaching jwt.Parse with a nil key set.
func TestTokenVerifier_Verify_EnsureFreshFailsNoSet(t *testing.T) {
	v := &TokenVerifier{
		jwksURL: "http://127.0.0.1:1/certs", // unreachable — fetch always fails
		issuer:  testIssuer, audience: testAudience,
		client: &http.Client{Timeout: time.Second},
	}
	_, err := v.Verify(context.Background(), "some.bearer.token")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// rotatingJWKS serves whichever fakeJWKSServer's key set is current — a stand-in for Keycloak
// rotating its realm signing key — and counts every fetch the verifier makes.
type rotatingJWKS struct {
	*httptest.Server
	current atomic.Pointer[fakeJWKSServer]
	fetches atomic.Int64
}

func newRotatingJWKS(t *testing.T, initial *fakeJWKSServer) *rotatingJWKS {
	t.Helper()
	r := &rotatingJWKS{}
	r.current.Store(initial)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.fetches.Add(1)
		resp, err := http.Get(r.current.Load().URL + "/certs")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(r.Close)
	return r
}

// TestTokenVerifier_UnknownKid_RefetchesOnce proves key rotation no longer costs up to a
// cache TTL of 401s: a token under a kid the cached set lacks triggers exactly one JWKS refetch
// (shared by every concurrent caller) and then validates; a second unknown kid inside the
// jwksKidMissInterval window is rejected WITHOUT another fetch (rate limit).
func TestTokenVerifier_UnknownKid_RefetchesOnce(t *testing.T) {
	keyA, keyB, keyC := newFakeJWKSServer(t), newFakeJWKSServer(t), newFakeJWKSServer(t)
	rot := newRotatingJWKS(t, keyA)
	v := newTestVerifier(t, rot.URL+"/certs")
	if got := rot.fetches.Load(); got != 1 {
		t.Fatalf("initial fetches = %d, want 1", got)
	}

	// Rotate: Keycloak now signs with key B, which the cached set (A only) does not carry.
	rot.current.Store(keyB)
	tokB := keyB.signToken(t, tokenOpts{audience: []string{testAudience}})

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.Verify(context.Background(), tokB)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: Verify after rotation = %v, want nil (refetched JWKS)", i, err)
		}
	}
	if got := rot.fetches.Load(); got != 2 {
		t.Fatalf("fetches after one rotation with %d concurrent callers = %d, want exactly 2 (single-flight)", callers, got)
	}

	// Rate limit: another unknown kid within jwksKidMissInterval must not fetch again.
	rot.current.Store(keyC)
	tokC := keyC.signToken(t, tokenOpts{audience: []string{testAudience}})
	if _, err := v.Verify(context.Background(), tokC); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("Verify with a second unknown kid inside the window = %v, want ErrTokenInvalid", err)
	}
	if got := rot.fetches.Load(); got != 2 {
		t.Fatalf("fetches after a rate-limited miss = %d, want still 2", got)
	}

	// Window elapsed: the miss may fetch again and the token validates.
	v.kidMissMu.Lock()
	v.lastKidRefetch = time.Now().Add(-jwksKidMissInterval - time.Second)
	v.kidMissMu.Unlock()
	if _, err := v.Verify(context.Background(), tokC); err != nil {
		t.Fatalf("Verify after the window = %v, want nil", err)
	}
	if got := rot.fetches.Load(); got != 3 {
		t.Fatalf("fetches after the window = %d, want 3", got)
	}
}

// TestTokenVerifier_KnownKidBadSignature_NoRefetch proves a forged token under a KNOWN kid is
// rejected without touching the JWKS endpoint — only an unknown kid earns a refetch.
func TestTokenVerifier_KnownKidBadSignature_NoRefetch(t *testing.T) {
	keyA := newFakeJWKSServer(t)
	rot := newRotatingJWKS(t, keyA)
	v := newTestVerifier(t, rot.URL+"/certs")

	other := newFakeJWKSServer(t)
	other.keyID = keyA.keyID // same kid, different private key
	forged := other.signToken(t, tokenOpts{audience: []string{testAudience}})
	if _, err := v.Verify(context.Background(), forged); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("Verify(forged) = %v, want ErrTokenInvalid", err)
	}
	if got := rot.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 (no refetch for a known kid)", got)
	}
}

// TestToken_ClockSkewTolerance proves the 30s acceptable skew on iat/nbf/exp: a token from a
// clock 20s ahead (iat/nbf in the future) or 20s behind (exp just past) validates; 60s does not.
func TestToken_ClockSkewTolerance(t *testing.T) {
	srv := newFakeJWKSServer(t)
	v := newTestVerifier(t, srv.URL+"/certs")
	now := time.Now()
	aud := []string{testAudience}

	cases := []struct {
		name string
		opts tokenOpts
		ok   bool
	}{
		{"iat 20s ahead", tokenOpts{audience: aud, issuedAt: now.Add(20 * time.Second)}, true},
		{"nbf 20s ahead", tokenOpts{audience: aud, notBefore: now.Add(20 * time.Second)}, true},
		{"exp 20s ago", tokenOpts{audience: aud, expiresAt: now.Add(-20 * time.Second)}, true},
		{"iat 60s ahead", tokenOpts{audience: aud, issuedAt: now.Add(60 * time.Second)}, false},
		{"nbf 60s ahead", tokenOpts{audience: aud, notBefore: now.Add(60 * time.Second)}, false},
		{"exp 60s ago", tokenOpts{audience: aud, expiresAt: now.Add(-60 * time.Second)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), srv.signToken(t, tc.opts))
			if tc.ok && err != nil {
				t.Fatalf("Verify = %v, want nil (within 30s skew)", err)
			}
			if !tc.ok && !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("Verify = %v, want ErrTokenInvalid (beyond 30s skew)", err)
			}
		})
	}
}
