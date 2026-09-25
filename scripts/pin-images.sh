#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Digest-pins every third-party base image (`make pin-images`): each `FROM <ref>` in the
# Dockerfiles and `image: <ref>` in compose/k8s below is rewritten to `<ref>@sha256:<digest>`,
# resolving the tag's CURRENT multi-arch index digest via `docker buildx imagetools inspect`.
# First-party `kiban-*` images, `${...}`-templated refs and build-stage names (no tag) are left
# alone. Re-run to move a pin
# (bump the tag first if you want a newer version — the tag stays as the human-readable intent,
# the digest is what actually gets pulled). `make quickstart-compose` afterwards carries the
# postgres pin into the generated quickstart file.
set -euo pipefail
cd "$(dirname "$0")/.."

files=(
  infra/Dockerfile.service
  infra/keycloak-build/Dockerfile
  deploy/k8s/demo-reset/Dockerfile
  infra/compose.yaml
  deploy/k8s/base/postgres.yaml
)

refs="$(grep -hoE '^(FROM|[[:space:]]*image:)[[:space:]]+[^[:space:]]+' "${files[@]}" \
  | awk '{print $2}' | grep ':' | grep -vE '^kiban-|\$\{' | sed 's/@sha256:[0-9a-f]*$//' | sort -u)"

for ref in $refs; do
  digest="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}')"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "pin-images: no digest for $ref: $digest" >&2; exit 1; }
  # Only FROM/image: lines (never comments); `ref` may carry regex metacharacters, so it is
  # matched literally via awk index().
  for f in "${files[@]}"; do
    awk -v ref="$ref" -v digest="$digest" '
      ($1 == "FROM" || $1 == "image:") && (i = index($0, ref)) {
        rest = substr($0, i + length(ref)); sub(/^@sha256:[0-9a-f]*/, "", rest)
        $0 = substr($0, 1, i - 1) ref "@" digest rest
      }
      { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
  echo "pin-images: $ref@$digest"
done
