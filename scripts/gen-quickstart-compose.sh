#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Generates deploy/quickstart/docker-compose.yml from infra/compose.yaml (stdout).
# `make quickstart-compose` writes it; `make docs-freshness-check` diffs it. The transformation
# is the zero-clone shape: no `build:`, GHCR images pinned by ${KIBAN_VERSION}, no dev-only
# services (profiles, source-built one-shots), the gateway in plain-HTTP mode, env defaults from
# deploy/quickstart/.env.example, and the postgres init SQL inlined as a compose `config`.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'EOF'
import re, sys, pathlib, yaml

REGISTRY = "ghcr.io/rosschiu/"
TAG = "${KIBAN_VERSION:?set KIBAN_VERSION in .env}"
VOLUME_PREFIX = "kiban-quickstart-"
ISSUER = ("https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT:-8443}",
          "http://localhost:${KIBAN_GATEWAY_HTTP_HOST_PORT:-3000}")

src = yaml.safe_load(open("infra/compose.yaml"))
services = src["services"]

# Env defaults: every `${VAR}` in the source takes its value from .env.example as `:-default`;
# a blank line there means the user must set it (`:?`).
defaults = {}
for line in open("deploy/quickstart/.env.example"):
    m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.rstrip("\n"))
    if m:
        defaults[m[1]] = m[2]

def rewrite(s):
    if not isinstance(s, str):
        return s
    s = s.replace(*ISSUER)
    def sub(m):
        v = m[1]
        if v not in defaults:
            return m[0]
        return "${%s:-%s}" % (v, defaults[v]) if defaults[v] else "${%s:?set a strong value in .env}" % v
    return re.sub(r"\$\{([A-Z0-9_]+)\}", sub, s)

def walk(x):
    if isinstance(x, dict):
        return {k: walk(v) for k, v in x.items()}
    if isinstance(x, list):
        return [walk(v) for v in x]
    return rewrite(x)

# Dev-only services: profile-gated fixtures, and the self-signed-cert one-shot (the quickstart
# gateway runs in plain-HTTP mode — no cert; the image exists only so KIBAN_IMAGE_TAG deploys of
# the TLS shape never build it from a checkout).
dropped = {n for n, s in services.items() if s.get("profiles")} | {"gateway-devcert"}
# ...and the named volumes they shared with a kept service (the devcert's TLS volume).
dropped_vols = {v.split(":", 1)[0] for n in dropped for v in services[n].get("volumes", [])}
services = {n: s for n, s in services.items() if n not in dropped}

configs = {}
for name, s in services.items():
    s.pop("build", None)
    # Compose secrets (infra/compose.yaml's `secrets:`, mounted from the project's own .env) are
    # not carried over: the quickstart keeps the plain `<VAR>` env var for every `<VAR>_FILE`
    # that pointed at one — its documented weaker posture (README.md), same values from .env.
    s.pop("secrets", None)
    for k in [k for k, v in s.get("environment", {}).items() if k.endswith("_FILE") and str(v).startswith("/run/secrets/")]:
        del s["environment"][k]
        s["environment"][k[: -len("_FILE")]] = "${%s}" % k[: -len("_FILE")]
    m = re.fullmatch(r"kiban-(\w+):\$\{KIBAN_IMAGE_TAG:-latest\}", s["image"])
    if m:
        s["image"] = REGISTRY + "kiban-" + m[1] + ":" + TAG
    for dep in dropped:
        s.get("depends_on", {}).pop(dep, None)
    # Env values that name a dropped service point at nothing on purpose (the notification
    # worker's SMTP host: it logs and retries instead of crashing).
    for k, v in s.get("environment", {}).items():
        if v in dropped:
            s["environment"][k] = "localhost"
    vols = []
    for v in s.get("volumes", []):
        host = v.split(":", 1)[0]
        if host in dropped_vols:
            continue
        if host in src["volumes"]:
            vols.append(VOLUME_PREFIX + v[len("kiban-"):])
        elif host == "./postgres-init":
            # A zero-clone checkout has no repo file to bind-mount: inline each init file.
            for f in sorted(pathlib.Path("infra/postgres-init").iterdir()):
                key = re.sub(r"\W", "_", f.stem)
                configs[key] = {"content": f.read_text()}
                s.setdefault("configs", []).append({"source": key, "target": "/docker-entrypoint-initdb.d/" + f.name})
        else:
            vols.append(v)
    if vols:
        s["volumes"] = vols
    elif "volumes" in s:
        del s["volumes"]

# The gateway runs its dev-only plain-HTTP listener (:8090): no gateway-devcert image, no domain
# for a real TLS mode. Same mode infra/compose.public.yaml uses behind a reverse proxy.
gw = services["gateway"]
gw["environment"].update({"KIBAN_TLS_CERT_FILE": "", "KIBAN_TLS_KEY_FILE": "", "KIBAN_INSECURE_HTTP": "true"})
gw["ports"] = [p.replace(":-8090}", ":-3000}") for p in gw["ports"] if p.endswith(":8090")]
gw["healthcheck"]["test"] = [t.replace("curl -sk", "curl -s").replace("https://127.0.0.1:8443/", "http://127.0.0.1:8090/")
                             for t in gw["healthcheck"]["test"]]

used = {v.split(":", 1)[0] for s in services.values() for v in s.get("volumes", []) if v.startswith(VOLUME_PREFIX)}
out = {"services": walk(services), "volumes": {v: {} for v in sorted(used)}, "configs": configs}

def literal(dumper, s):  # multi-line strings (the inlined SQL) as `|` blocks
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s and "\r" not in s else None)
yaml.add_representer(str, literal, Dumper=yaml.SafeDumper)

sys.stdout.write("""\
# GENERATED by scripts/gen-quickstart-compose.sh from infra/compose.yaml — do not edit by hand;
# run `make quickstart-compose` (checked by `make docs-freshness-check`). Read README.md first.
#
# Kiban zero-clone quickstart: every image is `ghcr.io/rosschiu/kiban-<service>:${KIBAN_VERSION}`
# (plus `postgres:18-alpine`); there is no `build:` and no repo checkout. Compared with the source
# file: `migrate`/`bootstrap`/`keycloak` ship as GHCR images, `gateway-devcert` and the `test`
# profile fixtures are dropped, the gateway runs its dev-only plain-HTTP listener on host port
# 3000 (no TLS), and the postgres init SQL is inlined as a compose `config`.
#
# Default port 3000 is deliberate: with no KIBAN_DOMAIN, bootstrap registers only fixed
# dev-loopback redirect URIs (http://localhost:3000, :5173) on the realm, so a browser login only
# completes from that origin. Use the SAME host:port every time you sign in — KEYCLOAK_ISSUER_URL
# is a string compared against the token's `iss` claim.
""")
yaml.safe_dump(out, sys.stdout, sort_keys=False, default_flow_style=False, width=1000, allow_unicode=True)
EOF
