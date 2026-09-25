// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/gateway"
	"github.com/rosschiu/kiban/internal/livestack"
)

// This package's own copy of the small dbtest env-loading helper every other integration-tested
// package duplicates rather than shares (see internal/identity/dbtest_test.go's header comment).
// run() is exercised against this repo's own dev-stack Keycloak (never mocked) — Postgres is not
// involved here at all (the gateway holds no DB pool of its own).

func testEnv(t *testing.T, name string) string { return livestack.Env(t, name) }

// setGatewayEnv sets every env var run()'s config.Spec reads to real dev-stack values, with
// KIBAN_INSECURE_HTTP left at the safe default (false). The listener ports are fixed (8443/8090),
// and the compose stack's own gateway container publishes exactly those on 127.0.0.1 — so a
// host-run test process binds the second loopback address instead (127.0.0.2 routes locally on
// Linux, the same trick modules/notification's pinned-dial test relies on).
const (
	testListenHost = "127.0.0.2"
	testDevHTTPURL = "http://" + testListenHost + ":" + devHTTPPort + "/api/health"
	testTLSURL     = "https://" + testListenHost + ":" + tlsPort + "/api/health"
)

func setGatewayEnv(t *testing.T) {
	t.Helper()
	realm := testEnv(t, "KEYCLOAK_REALM")
	kcHostPort := testEnv(t, "KEYCLOAK_HOST_PORT")
	env := map[string]string{
		"KIBAN_LISTEN_ADDR":       testListenHost,
		"KEYCLOAK_BASE_URL":       "http://127.0.0.1:" + kcHostPort,
		"KEYCLOAK_JWKS_URL":       "http://127.0.0.1:" + kcHostPort + "/realms/" + realm + "/protocol/openid-connect/certs",
		"KEYCLOAK_ISSUER_URL":     "http://127.0.0.1:" + kcHostPort + "/realms/" + realm,
		"KEYCLOAK_AUDIENCE":       "kiban-api",
		"KIBAN_REGISTRY_BASE_URL": "http://127.0.0.1:1",
		"KIBAN_AUTHZ_BASE_URL":    "http://127.0.0.1:1",
		"KIBAN_ORG_BASE_URL":      "http://127.0.0.1:1",
		"KIBAN_IDENTITY_BASE_URL": "http://127.0.0.1:1", // never dialed at startup, only on a first authenticated request
		"KIBAN_STATIC_DIR":        "",
		"KIBAN_DOMAIN":            "",
		"KIBAN_TLS_CERT_FILE":     "",
		"KIBAN_TLS_KEY_FILE":      "",
		"KIBAN_INSECURE_HTTP":     "false",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// generateSelfSignedCert writes a throwaway self-signed cert/key pair to two files under t's
// temp dir, for the operator-cert TLS mode's own test — never a real CA, never committed
// anywhere, generated fresh per test.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kiban-gateway-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyOut.Close()

	return certFile, keyFile
}

// --- buildTLSConfig unit tests (tls.go) ---

// TestBuildTLSConfig_NeitherSet_ReturnsNilNil proves the fallback case: no
// operator cert/key pair configured returns (nil, nil), the signal run() uses to fall through to
// the dev-HTTP branch.
func TestBuildTLSConfig_NeitherSet_ReturnsNilNil(t *testing.T) {
	cfg, err := buildTLSConfig(map[string]string{
		"KIBAN_TLS_CERT_FILE": "", "KIBAN_TLS_KEY_FILE": "",
	})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %+v, want nil", cfg)
	}
}

// TestBuildTLSConfig_OperatorCerts_Success proves the operator-cert branch loads a real
// cert/key pair into a *tls.Config with no network involvement at all.
func TestBuildTLSConfig_OperatorCerts_Success(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)
	cfg, err := buildTLSConfig(map[string]string{
		"KIBAN_TLS_CERT_FILE": certFile, "KIBAN_TLS_KEY_FILE": keyFile,
	})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("cfg = %+v, want one loaded certificate", cfg)
	}
}

// TestBuildTLSConfig_OperatorCerts_LoadErrorWrapped proves the operator-cert branch's own error
// path: a cert/key pair pointing at files that don't parse as X.509 surfaces a wrapped error,
// not a panic or a silently-nil config.
func TestBuildTLSConfig_OperatorCerts_LoadErrorWrapped(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badFile, []byte("not a real certificate"), 0o600); err != nil {
		t.Fatalf("write bad cert file: %v", err)
	}

	_, err := buildTLSConfig(map[string]string{
		"KIBAN_TLS_CERT_FILE": badFile, "KIBAN_TLS_KEY_FILE": badFile,
	})
	if err == nil {
		t.Fatal("buildTLSConfig: want error for an unparseable cert/key pair, got nil")
	}
	if !strings.Contains(err.Error(), "load operator TLS cert/key") {
		t.Errorf("err = %v, want it to wrap \"load operator TLS cert/key\"", err)
	}
}

// --- run() tests ---

// TestRun_MissingConfigErrors proves run() surfaces config.Load's MissingError as a wrapped
// "load config" failure, before any network call is attempted — the fast, infra-free path.
func TestRun_MissingConfigErrors(t *testing.T) {
	for _, k := range []string{
		"KIBAN_LISTEN_ADDR", "KEYCLOAK_BASE_URL", "KEYCLOAK_JWKS_URL", "KEYCLOAK_ISSUER_URL",
		"KEYCLOAK_AUDIENCE", "KIBAN_REGISTRY_BASE_URL", "KIBAN_AUTHZ_BASE_URL", "KIBAN_IDENTITY_BASE_URL", "KIBAN_STATIC_DIR",
		"KIBAN_DOMAIN", "KIBAN_TLS_CERT_FILE", "KIBAN_TLS_KEY_FILE", "KIBAN_INSECURE_HTTP",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	// KEYCLOAK_BASE_URL/JWKS_URL/ISSUER_URL intentionally left unset (all Required: true).

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("err = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_TokenVerifierBuildErrors proves the "build token verifier" failure branch: an
// unreachable JWKS URL fails NewTokenVerifier's initial fetch, and run() surfaces it wrapped.
func TestRun_TokenVerifierBuildErrors(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("KEYCLOAK_JWKS_URL", "http://127.0.0.1:1/certs") // unreachable

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an unreachable JWKS endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "build token verifier") {
		t.Errorf("err = %v, want it to wrap \"build token verifier\"", err)
	}
}

// TestRun_CatalogMaxStaleParseErrors proves the "parse KIBAN_CATALOG_MAX_STALE" branch: an
// unparseable duration fails run() after the verifier is built and before any listener binds.
func TestRun_CatalogMaxStaleParseErrors(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("KIBAN_CATALOG_MAX_STALE", "not-a-duration")

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an unparseable KIBAN_CATALOG_MAX_STALE, got nil")
	}
	if !strings.Contains(err.Error(), "parse KIBAN_CATALOG_MAX_STALE") {
		t.Errorf("err = %v, want it to wrap \"parse KIBAN_CATALOG_MAX_STALE\"", err)
	}
}

// TestRun_TLSConfigBuildErrors proves run()'s "build TLS config" branch: an operator cert/key
// pair that does not parse surfaces wrapped, before any listener binds.
func TestRun_TLSConfigBuildErrors(t *testing.T) {
	setGatewayEnv(t)
	badFile := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(badFile, []byte("not a real certificate"), 0o600); err != nil {
		t.Fatalf("write bad cert file: %v", err)
	}
	t.Setenv("KIBAN_TLS_CERT_FILE", badFile)
	t.Setenv("KIBAN_TLS_KEY_FILE", badFile)

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error for an unparseable cert/key pair, got nil")
	}
	if !strings.Contains(err.Error(), "build TLS config") {
		t.Errorf("err = %v, want it to wrap \"build TLS config\"", err)
	}
}

// TestRun_InsecureHTTPRefusedByDefault proves the refusal path: no TLS configured and
// KIBAN_INSECURE_HTTP not "true" fails loudly rather than silently serving plaintext.
func TestRun_InsecureHTTPRefusedByDefault(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("KIBAN_INSECURE_HTTP", "false")

	err := run(context.Background(), testLogger())
	if err == nil {
		t.Fatal("run: want error (no TLS configured, insecure HTTP not opted in), got nil")
	}
	if !strings.Contains(err.Error(), "refusing to serve plaintext") {
		t.Errorf("err = %v, want it to mention refusing plaintext", err)
	}
}

// TestRun_DevHTTP_StartsAndShutsDownGracefully proves the dev-HTTP path end to end: real
// Keycloak JWKS fetch, real routes, a real plaintext HTTP listener actually accepting a request,
// and a clean graceful shutdown when ctx is cancelled.
func TestRun_DevHTTP_StartsAndShutsDownGracefully(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("KIBAN_INSECURE_HTTP", "true")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, testLogger()) }()

	addr := testDevHTTPURL
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("gateway (dev-HTTP) never came up at %s: %v", addr, lastErr)
	}

	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of ctx cancellation — graceful shutdown hung")
	}
}

// TestRun_TLS_StartsAndShutsDownGracefully proves the TLS (operator-cert) path end to end: the
// HTTPS listener actually accepts a request (self-signed cert, InsecureSkipVerify client-side —
// this proves the server's own TLS wiring, not certificate trust) and shuts down cleanly on ctx
// cancellation.
func TestRun_TLS_StartsAndShutsDownGracefully(t *testing.T) {
	setGatewayEnv(t)
	certFile, keyFile := generateSelfSignedCert(t)
	t.Setenv("KIBAN_TLS_CERT_FILE", certFile)
	t.Setenv("KIBAN_TLS_KEY_FILE", keyFile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, testLogger()) }()

	httpsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only, self-signed
	}}

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	up := false
	for time.Now().Before(deadline) {
		resp, err := httpsClient.Get(testTLSURL)
		if err == nil {
			resp.Body.Close()
			up = true
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Fatalf("gateway (TLS) never came up at %s: %v", testTLSURL, lastErr)
	}

	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of ctx cancellation — graceful shutdown hung")
	}
}

// TestRun_ListenAddrConflictErrors proves serveDevHTTP's "serveErr" branch: a second run() bound
// to a dev-HTTP address a first, still-live run() already holds fails via ListenAndServe's own
// "address already in use" error, surfaced as run()'s return value.
func TestRun_ListenAddrConflictErrors(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("KIBAN_INSECURE_HTTP", "true")

	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstErr := make(chan error, 1)
	go func() { firstErr <- run(firstCtx, testLogger()) }()

	addr := testDevHTTPURL
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			resp.Body.Close()
			up = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Fatal("first run() never came up — cannot prove the conflict")
	}

	secondErr := run(context.Background(), testLogger())
	if secondErr == nil {
		t.Fatal("run: want error for a listen-address conflict, got nil")
	}

	firstCancel()
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first run(): want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first run() did not return within 10s of ctx cancellation")
	}
}

// TestRun_TLSPortConflictErrors proves serveTLS's TLS-listener "serveErr" branch: a second
// run() bound to a TLS address a first, still-live run() already holds fails via
// ListenAndServeTLS's own "address already in use" error, surfaced as run()'s return value.
func TestRun_TLSPortConflictErrors(t *testing.T) {
	setGatewayEnv(t)
	certFile, keyFile := generateSelfSignedCert(t)
	t.Setenv("KIBAN_TLS_CERT_FILE", certFile)
	t.Setenv("KIBAN_TLS_KEY_FILE", keyFile)

	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstErr := make(chan error, 1)
	go func() { firstErr <- run(firstCtx, testLogger()) }()

	httpsClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only, self-signed
	}}
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, err := httpsClient.Get(testTLSURL)
		if err == nil {
			resp.Body.Close()
			up = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		t.Fatal("first run() (TLS) never came up — cannot prove the conflict")
	}

	secondCertFile, secondKeyFile := generateSelfSignedCert(t)
	t.Setenv("KIBAN_TLS_CERT_FILE", secondCertFile)
	t.Setenv("KIBAN_TLS_KEY_FILE", secondKeyFile)

	secondErr := run(context.Background(), testLogger())
	if secondErr == nil {
		t.Fatal("run: want error for a TLS listen-address conflict, got nil")
	}
	if !strings.Contains(secondErr.Error(), "tls listener") {
		t.Errorf("err = %v, want it to wrap \"tls listener\"", secondErr)
	}

	firstCancel()
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first run(): want nil after graceful shutdown, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first run() did not return within 10s of ctx cancellation")
	}
}

// TestRefreshJWKSPeriodically_TicksAndRefreshes proves the ticker.C branch (never exercised by
// the full run() tests above, whose interval is a real 10 minutes): with a short interval
// injected directly, the goroutine actually calls verifier.Refresh on each tick until ctx is
// cancelled.
func TestRefreshJWKSPeriodically_TicksAndRefreshes(t *testing.T) {
	realm := testEnv(t, "KEYCLOAK_REALM")
	kcHostPort := testEnv(t, "KEYCLOAK_HOST_PORT")
	jwksURL := "http://127.0.0.1:" + kcHostPort + "/realms/" + realm + "/protocol/openid-connect/certs"
	issuerURL := "http://127.0.0.1:" + kcHostPort + "/realms/" + realm

	verifier, err := gateway.NewTokenVerifier(context.Background(), jwksURL, issuerURL, "kiban-api")
	if err != nil {
		t.Fatalf("NewTokenVerifier: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		refreshJWKSPeriodically(ctx, testLogger(), verifier, 20*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshJWKSPeriodically did not return within 5s of ctx expiry")
	}
}
