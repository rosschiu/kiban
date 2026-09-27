// SPDX-License-Identifier: Apache-2.0

// Sidebar nav entries + company-switcher data, composed from the same SDK surfaces
// module-access.ts fetches (the company switcher is fed by
// org.meCompanies + the SDK session context). A separate hook from `useModuleAccess` (rather than
// sharing its state) because its caller (guarded-root.tsx) is a different part of the tree with a
// different lifecycle — GuardedRoot is the one place already reactive to both `isAuthenticated`
// (useShellSession) and `activeCompanyId` (useCompanyContext), so it is also the natural place to
// re-derive nav entries whenever either changes, without threading extra params through
// module-route-host.tsx's unchanged `useModuleAccess()` call.
import type { OrgMeCompany } from "@rosschiu/kiban-sdk";
import { useEffect, useState } from "react";
import { localModuleRegistry } from "../modules/registry";
import { getCompanySessionContext } from "./company-context";
import { computeModuleAccess, computeNavEntries } from "./compose";
import { fetchPlatformCompositionCached, getCompositionSnapshot } from "./module-access";
import { useNavBadges } from "./nav-badges";
import type { NavEntry } from "./sidebar-nav";

export interface NavState {
  entries: readonly NavEntry[];
  companies: readonly OrgMeCompany[];
  /** false while the session's first composition fetch is still in flight (
   * loading must be distinguishable from a genuinely empty catalog). */
  ready: boolean;
  /** Set when the composition could not be fetched because a service was down — the sidebar
   * renders this instead of "No modules installed". */
  unavailable?: string;
}

const emptyNavState: NavState = { entries: [], companies: [], ready: false };
const signedOutNavState: NavState = { entries: [], companies: [], ready: true };

/** Empty (never loading-aware — the empty state IS the correct render, same posture as
 * SidebarNav itself) until `isAuthenticated` is true, at which point it fetches the
 * full composition and re-derives nav entries whenever `activeCompanyId` changes (a company-
 * scoped module's entry depends on which company is active — compose.ts's `computeNavEntries`). */
export function useNavState(isAuthenticated: boolean, activeCompanyId: string | null): NavState {
  const [state, setState] = useState<NavState>(() => {
    // Synchronous initial read: after the session's first fetch, remounts render the real nav
    // immediately — no "No modules installed" flash on navigation.
    const snap = getCompositionSnapshot();
    if (!isAuthenticated || !snap) return isAuthenticated ? emptyNavState : signedOutNavState;
    const access = computeModuleAccess(snap);
    return {
      entries: computeNavEntries(access, snap.catalog, localModuleRegistry, activeCompanyId),
      companies: snap.meCompanies,
      ready: true,
      unavailable: snap.unavailable ?? undefined,
    };
  });
  // Unconditional hook call, same posture as module-access.ts's useModuleAccess — degrades to an
  // empty badge map (no per-entry useUnreadCount ever fires against a real company) whenever
  // unauthenticated, since callers pass `activeCompanyId` through unchanged either way.
  const badges = useNavBadges(isAuthenticated ? activeCompanyId : null);

  useEffect(() => {
    let cancelled = false;
    if (!isAuthenticated) {
      setState(signedOutNavState);
      return;
    }

    fetchPlatformCompositionCached()
      .then((data) => {
        if (cancelled) return;
        // Reconcile the client-persisted selection (SDK SessionContext, localStorage — survives
        // reloads and redeploys) against the memberships the server just reported: a persisted
        // activeCompanyId the caller no longer belongs to (deleted company, rebuilt database)
        // must not keep driving company-scoped fetches into guaranteed 403s. Only reconcile
        // against a NON-empty list — meCompanies fails closed to [] on a transient fetch error
        // (module-access.ts), and dropping a valid selection on a blip would be worse than
        // keeping a stale one (which renders no module entries anyway).
        if (
          activeCompanyId &&
          data.meCompanies.length > 0 &&
          !data.meCompanies.some((company) => company.id === activeCompanyId)
        ) {
          getCompanySessionContext().setActiveCompanyId(null);
          return; // subscribers re-render; this effect re-runs with the cleared selection
        }
        const access = computeModuleAccess(data);
        const entries = computeNavEntries(access, data.catalog, localModuleRegistry, activeCompanyId);
        setState({ entries, companies: data.meCompanies, ready: true, unavailable: data.unavailable ?? undefined });
      })
      .catch(() => {
        // fetch failed: resolved-empty (ready) so the UI shows the honest empty state, and the
        // next navigation retries (the cache never keeps a rejection).
        if (!cancelled) setState({ entries: [], companies: [], ready: true });
      });

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, activeCompanyId]);

  const entries = state.entries.map((entry): NavEntry => {
    const badge = badges[entry.moduleKey];
    return badge ? { ...entry, badge } : entry;
  });

  return { entries, companies: state.companies, ready: state.ready, unavailable: state.unavailable };
}
