// SPDX-License-Identifier: Apache-2.0

// The gateway's TLS modes: :8443 TLS with operator certs via KIBAN_TLS_CERT_FILE/KEY_FILE; else
// KIBAN_INSECURE_HTTP=true plain HTTP on :8090 (dev, or behind a TLS-terminating proxy).
package main

import (
	"crypto/tls"
	"fmt"
)

// buildTLSConfig loads the operator-supplied cert/key pair from values. A nil,nil result means
// no TLS is configured — the caller falls back to plain HTTP, gated on KIBAN_INSECURE_HTTP.
func buildTLSConfig(values map[string]string) (*tls.Config, error) {
	certFile, keyFile := values["KIBAN_TLS_CERT_FILE"], values["KIBAN_TLS_KEY_FILE"]
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load operator TLS cert/key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	return nil, nil
}
