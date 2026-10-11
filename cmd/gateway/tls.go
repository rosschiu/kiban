// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// buildTLSConfig picks the listener's TLS shape from the environment, in priority order:
//
//  1. KIBAN_TLS_CERT_FILE + KIBAN_TLS_KEY_FILE: an operator-supplied certificate.
//  2. KIBAN_TLS_SELF_SIGNED_DIR: development only. The gateway generates a self-signed
//     certificate for localhost on first start, keeps the pair in that directory (a volume in
//     infra/compose.yaml, so a restart does not change the certificate clients have trusted)
//     and reuses it afterwards. No sidecar, no openssl.
//  3. neither: nil, and run() requires KIBAN_INSECURE_HTTP=true (behind a TLS-terminating edge).
func buildTLSConfig(values map[string]string) (*tls.Config, error) {
	certFile, keyFile := values["KIBAN_TLS_CERT_FILE"], values["KIBAN_TLS_KEY_FILE"]
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load operator TLS cert/key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	if dir := values["KIBAN_TLS_SELF_SIGNED_DIR"]; dir != "" {
		cert, err := selfSignedPair(dir)
		if err != nil {
			return nil, fmt.Errorf("self-signed development TLS: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	return nil, nil
}

const (
	selfSignedCertName = "dev.crt"
	selfSignedKeyName  = "dev.key"
)

// selfSignedPair loads dir/dev.crt + dir/dev.key, generating and writing them when either is
// missing: ECDSA P-256, CN localhost, SANs localhost and 127.0.0.1, ten years.
func selfSignedPair(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, selfSignedCertName), filepath.Join(dir, selfSignedKeyName)
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, fmt.Errorf("load %s: %w", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", certPath, err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
