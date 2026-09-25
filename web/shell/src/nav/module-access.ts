// SPDX-License-Identifier: Apache-2.0

// Resolver access inputs, sourced from the catalog/capability/access-summary composition.
// Auth state is NOT read here: `GuardedRoot` (the only ancestor of every consumer) is the one
// source of truth for "signed in" and never mounts a route host for a visitor it is redirecting.
// A second, live read of the session here disagreed with GuardedRoot's snapshot for an
// expired-but-refreshable token and rendered "Module unavailable" instead of letting the fetch's
// 401 path refresh.
import {
  createCapabilitiesClient,
  createEffectiveAccessClient,
  createOrgClient,
  createSuperadminClient
} from "@rosschiu/kiban-sdk";
import { useEffect, useState } from "react";
import { getShellSdk } from "../auth/sdk";
import { describeApiError, isServiceFailure } from "../lib/api-error";
import { computeModuleAccess, emptyModuleAccess, type PlatformComposition } from "./compose";

export type { ModuleAccess } from "./compose";

/** Fetches every SDK surface the nav composition depends on: capabilities (installed/enabled),
 * the platform catalog (scope/active/displayName), the caller's global-scope effective-access
 * summary, and — for every company the caller belongs to (org.meCompanies) — that company's own
 * summary. Every leaf fails closed (empty/null) rather than throwing, so one slow/broken module
 * never blocks the rest of the composition (the platform's fail-closed posture, applied to
 * reads: partial data degrades the nav/resolver inputs, it never crashes the shell). A leaf that
 * failed because a service was down (5xx/no connection — not a 401/403/404) is remembered in
 * `unavailable` so the sidebar can say "could not load" instead of "no modules installed". */
async function fetchPlatformComposition(): Promise<PlatformComposition> {
  const { apiClient } = getShellSdk();
  const capabilitiesClient = createCapabilitiesClient(apiClient);
  const superadminClient = createSuperadminClient(apiClient);
  const effectiveAccessClient = createEffectiveAccessClient(apiClient);
  const orgClient = createOrgClient(apiClient);

  let unavailable: string | null = null;
  const leaf = <T,>(promise: Promise<T>, fallback: T): Promise<T> =>
    promise.catch((err: unknown) => {
      if (!unavailable && isServiceFailure(err)) unavailable = describeApiError(err, "");
      return fallback;
    });

  const [capabilities, catalog, globalSummary, meCompanies] = await Promise.all([
    leaf(capabilitiesClient.list(), []),
    leaf(superadminClient.catalog(), []),
    leaf(effectiveAccessClient.summary(), null),
    leaf(orgClient.meCompanies(), [])
  ]);

  const companySummaryEntries = await Promise.all(
    meCompanies.map(async (company) => [company.id, await leaf(effectiveAccessClient.summary(company.id), null)] as const)
  );

  return {
    capabilities,
    catalog,
    globalSummary,
    meCompanies,
    companySummaries: new Map(companySummaryEntries),
    unavailable
  };
}

// --- Session-persistent composition. Re-fetching the whole composition (5+ round-trips) on
// every module-nav click would cause visible lag, and starting each route-host MOUNT from the
// empty shape would render "Module unavailable"/"No modules installed" for a frame or a fetch
// (loading indistinguishable from resolved-empty). So: ONE fetch per session, its resolved value
// held in a module-level
// snapshot every consumer reads SYNCHRONOUSLY on mount (no empty first render once resolved),
// with subscribers notified when it first lands. `ready=false` (snapshot absent) is a real,
// distinct loading state — consumers render a neutral pending UI, never the empty/unavailable
// copy. The composition is not company-scoped (it fetches every company's summary), so company
// switches need nothing; only auth changes invalidate (logout via auth/session-context). A
// rejected fetch never poisons the session — the next call retries fresh.
let compositionPromise: Promise<PlatformComposition> | null = null;
let compositionSnapshot: PlatformComposition | null = null;
const compositionListeners = new Set<() => void>();

function notifyCompositionListeners(): void {
  for (const listener of [...compositionListeners]) listener();
}

export function fetchPlatformCompositionCached(): Promise<PlatformComposition> {
  if (compositionPromise) return compositionPromise;
  const promise = fetchPlatformComposition();
  compositionPromise = promise;
  promise
    .then((data) => {
      if (compositionPromise === promise) {
        compositionSnapshot = data;
        notifyCompositionListeners();
      }
    })
    .catch(() => {
      if (compositionPromise === promise) compositionPromise = null;
    });
  return promise;
}

/** The synchronously-readable resolved composition — null until the session's first fetch
 * lands (the loading state). */
export function getCompositionSnapshot(): PlatformComposition | null {
  return compositionSnapshot;
}

function subscribeComposition(listener: () => void): () => void {
  compositionListeners.add(listener);
  return () => compositionListeners.delete(listener);
}

/** Drops the session's composition — call on any auth-state change (logout, fresh login). */
export function invalidatePlatformComposition(): void {
  compositionPromise = null;
  compositionSnapshot = null;
  notifyCompositionListeners();
}

/** Real SDK-backed hook. Reads the
 * session snapshot synchronously (instant on every mount after the first resolve) and exposes
 * `ready` so callers can render a REAL loading state instead of mistaking "still fetching" for
 * "resolved: nothing". Fails closed to the empty shape (ready=true) if the fetch rejects. */
export function useModuleAccess(): { access: ModuleAccessShape; ready: boolean } {
  const initial = compositionSnapshot;
  const [state, setState] = useState<{ access: ModuleAccessShape; ready: boolean }>(() =>
    initial ? { access: computeModuleAccess(initial), ready: true } : { access: emptyModuleAccess, ready: false }
  );

  useEffect(() => {
    let cancelled = false;
    const sync = () => {
      if (cancelled) return;
      const snap = compositionSnapshot;
      if (snap) setState({ access: computeModuleAccess(snap), ready: true });
    };
    const unsubscribe = subscribeComposition(sync);
    fetchPlatformCompositionCached()
      .then(sync)
      .catch(() => {
        if (!cancelled) setState({ access: emptyModuleAccess, ready: true });
      });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, []);

  return state;
}

type ModuleAccessShape = ReturnType<typeof computeModuleAccess>;
