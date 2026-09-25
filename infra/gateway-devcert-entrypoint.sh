#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Generates a self-signed TLS cert/key for the gateway's dev-stack "operator certs"
# mode (KIBAN_TLS_CERT_FILE/KEY_FILE), exercised here with a
# locally-generated cert instead of a real operator-supplied one. Idempotent: a cert already on the shared volume from a
# previous `make dev` is left alone, so `docker compose up` doesn't regenerate (and doesn't
# force every client to re-trust a new cert) on every restart — only `make dev-clean` (which
# drops the volume) makes it re-generate.
set -eu

out_dir="/certs"
cert="$out_dir/dev.crt"
key="$out_dir/dev.key"

if [ -f "$cert" ] && [ -f "$key" ]; then
  echo "gateway-devcert: existing cert found, leaving it in place"
else
  mkdir -p "$out_dir"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$key" -out "$cert" -days 3650 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  echo "gateway-devcert: generated a new self-signed dev certificate"
fi

# The gateway runs as uid 65532 (infra/Dockerfile.service runtime-base) and mounts this volume
# read-only; openssl writes the key 0600 root-owned, so hand it over every run (a volume from
# before the gateway went non-root is fixed the same way).
chown 65532:65532 "$cert" "$key"
