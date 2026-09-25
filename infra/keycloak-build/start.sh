#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Renders realm-kiban.json.template -> realm-kiban.json, substituting the one secret the
# static realm-import mechanism can't hold in plaintext: the identity service-account client
# secret comes from the container's own environment, not baked into the committed realm JSON.
# Pure bash parameter expansion — no sed (whose replacement string would mangle `|`, `&` and `\`
# in the secret) and no envsubst dependency. The secret is JSON-escaped first (`\` and `"`), so
# any operator-chosen value renders a valid realm import that Keycloak stores verbatim.
set -euo pipefail

: "${KEYCLOAK_IDENTITY_CLIENT_SECRET:?KEYCLOAK_IDENTITY_CLIENT_SECRET not set}"

template_file="/opt/keycloak/data/import/realm-kiban.json.template"
rendered_file="/opt/keycloak/data/import/realm-kiban.json"

# bash 5.2+ would otherwise treat `&` in the replacement as "the matched text".
shopt -u patsub_replacement 2>/dev/null || true
secret_json=${KEYCLOAK_IDENTITY_CLIENT_SECRET//\\/\\\\}
secret_json=${secret_json//\"/\\\"}
template=$(<"$template_file")
printf '%s\n' "${template//'${KEYCLOAK_IDENTITY_CLIENT_SECRET}'/$secret_json}" > "$rendered_file"

exec /opt/keycloak/bin/kc.sh "$@"
