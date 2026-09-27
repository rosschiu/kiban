#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Apply the full Kustomize manifest set in one shot, then GATE progress on staged
# `kubectl wait` calls in the exact dependency order infra/compose.yaml's own `depends_on` chain
# encodes (postgres -> keycloak -> migrate -> bootstrap -> the 9 app services), rather than
# initContainers on every Deployment (see deploy/k8s/README.md "Apply order"): every workload is safe
# to already exist before its dependency is ready — a Deployment just sits
# Pending/CrashLoopBackOff until its dependency answers (identity/org/authz's own DB-connection
# retry loops, same startup-race tolerance infra/compose.yaml relies on), and `kubectl wait`
# below makes that visible step by step instead of silently racing.
#
# Usage: deploy/k8s/apply.sh <kind|production> [namespace]
set -euo pipefail

overlay="${1:?usage: apply.sh <kind|production> [namespace]}"
ns="${2:-kiban}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
overlay_dir="$script_dir/overlays/$overlay"

log() { echo "[apply] $*"; }
fail() {
  echo "[apply] FAIL: $*" >&2
  exit 1
}

[ -d "$overlay_dir" ] || fail "no such overlay: $overlay_dir"
[ -f "$script_dir/base/secret.yaml" ] || fail "$script_dir/base/secret.yaml missing — run deploy/k8s/gen-secrets.sh first"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not on PATH"

# Re-runnable for an upgrade: a Job's pod template is immutable, so `kubectl apply` of the same
# Job name with a new image tag fails — and a leftover Complete Job would satisfy the waits
# below without the new version's migrations ever running. Delete both one-shots first (no-op
# on a first run: the namespace does not exist yet); the apply recreates them fresh.
if kubectl get namespace "$ns" >/dev/null 2>&1; then
  log "removing previous migrate/bootstrap Jobs (immutable spec; they rerun below)"
  kubectl -n "$ns" delete job migrate bootstrap --ignore-not-found --wait=true
fi

log "applying full manifest set (overlay: $overlay, namespace: $ns)"
kubectl apply -k "$overlay_dir"

log "stage 1 wait: postgres ready"
kubectl -n "$ns" rollout status statefulset/postgres --timeout=180s

log "stage 1 wait: keycloak ready"
kubectl -n "$ns" rollout status deployment/keycloak --timeout=300s

log "stage 2 wait: migrate Job complete"
kubectl -n "$ns" wait --for=condition=complete job/migrate --timeout=600s

log "stage 3 wait: bootstrap Job complete"
kubectl -n "$ns" wait --for=condition=complete job/bootstrap --timeout=600s

log "stage 4 wait: app services ready"
for svc in registry identity org authz notification timesheet docs helpdesk gateway; do
  kubectl -n "$ns" rollout status deployment/"$svc" --timeout=180s
done

log "done — every workload ready. Try: kubectl -n $ns port-forward svc/gateway 8090:8090"
