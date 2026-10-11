#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Renders the Kustomize tree without a cluster (wired into `make check`):
#   1. the base alone renders and contains NO Secret (so it is usable as a remote base);
#   2. each shipped overlay, with a generated secret, renders exactly one `kiban-secrets`;
#   3. an overlay in the shipped shape but outside this tree (a stand-in for one kept in another
#      repository) renders against the base with its own Secret.
# Works on a scratch copy so the real overlays' gitignored secret files are never touched.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v kubectl >/dev/null 2>&1 || { echo "[kustomize-check] FAIL: kubectl not on PATH" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp -R "$script_dir" "$work/k8s"
rm -f "$work"/k8s/base/secret.yaml "$work"/k8s/overlays/*/secret.yaml
fail() { echo "[kustomize-check] FAIL: $*" >&2; exit 1; }
secrets() { grep -c '^  name: kiban-secrets$' || true; }
# Every namespaced resource must render with `namespace: kiban`: the base's `namespace:` covers
# only the base's own resources, so a Secret listed by an overlay lands in the kubeconfig's
# current namespace unless the overlay (or the Secret itself) names it.
read -r -d '' ns_check <<'PY' || true
import sys, yaml
bad = []
for d in yaml.safe_load_all(sys.stdin):
    if not d or d["kind"] == "Namespace":
        continue
    if d["metadata"].get("namespace") != "kiban":
        bad.append(d["kind"] + "/" + d["metadata"]["name"])
print(" ".join(bad))
PY
namespaced() { python3 -c "$ns_check"; }

n="$(kubectl kustomize "$work/k8s/base" | secrets)"
[ "$n" = 0 ] || fail "base renders $n kiban-secrets Secret(s); it must carry none"

for ov in kind production; do
  "$work/k8s/gen-secrets.sh" "$ov" >/dev/null 2>&1
  [ -f "$work/k8s/overlays/$ov/secret.yaml" ] || fail "gen-secrets.sh $ov wrote nothing"
  n="$(kubectl kustomize "$work/k8s/overlays/$ov" | secrets)"
  [ "$n" = 1 ] || fail "overlay $ov renders $n kiban-secrets Secret(s), want 1"
  bad="$(kubectl kustomize "$work/k8s/overlays/$ov" | namespaced)"
  [ -z "$bad" ] || fail "overlay $ov renders resources outside the kiban namespace: $bad"
done

# 0.1.0 upgrade path: a secret left in base/ is moved, not regenerated.
rm -f "$work/k8s/overlays/kind/secret.yaml"
printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: kiban-secrets\nstringData:\n  MARKER: "from-0.1.0"\n' > "$work/k8s/base/secret.yaml"
"$work/k8s/gen-secrets.sh" kind >/dev/null 2>&1
grep -q 'from-0.1.0' "$work/k8s/overlays/kind/secret.yaml" || fail "gen-secrets.sh did not move the 0.1.0 base secret"
[ ! -f "$work/k8s/base/secret.yaml" ] || fail "the 0.1.0 base secret was copied, not moved"

# Remote-shaped overlay: lives outside the tree, references the base by path, brings its own Secret.
mkdir -p "$work/remote"
cat > "$work/remote/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../k8s/base
  - secret.yaml
YAML
cp "$work/k8s/base/secret.example.yaml" "$work/remote/secret.yaml"
n="$(kubectl kustomize "$work/remote" | secrets)"
[ "$n" = 1 ] || fail "remote-shaped overlay renders $n kiban-secrets Secret(s), want 1"
bad="$(kubectl kustomize "$work/remote" | namespaced)"
[ -z "$bad" ] || fail "remote-shaped overlay renders resources outside the kiban namespace: $bad"

echo "[kustomize-check] PASS: base has no Secret; kind, production and a remote-shaped overlay each render one, every resource in the kiban namespace"
