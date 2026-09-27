// SPDX-License-Identifier: Apache-2.0

import { Navigate, Outlet, useRouter } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useShellSession } from "../auth/session-context";
import { useCompanyContext } from "../nav/company-context";
import { getCompanySwitchDestination } from "../nav/company-switch-path";
import { useNavState } from "../nav/nav-state";
import { AppShell } from "../ui/app-shell";

/** The guarded root for everything under `/app`: unauthenticated visitors are redirected to
 * `/login`, never shown any app chrome or data. Also
 * the one place that composes the real nav/company-switcher data — it is
 * already the tree's single point reactive to both auth state and the active company, so it is
 * also the natural place to re-derive both whenever either changes. Hooks run unconditionally
 * (before the auth check) per the Rules of Hooks; each degrades to its own empty shape when
 * unauthenticated, so nothing is fetched for a visitor about to be redirected away.
 *
 * Deliberately reads the current pathname via `router.state.location.pathname` (a plain getter
 * on the router instance from `useRouter()`, which subscribes to nothing) rather than the
 * reactive `useLocation()` hook: `useLocation()` re-renders this component on every router state
 * tick, which — combined with the `<Navigate>` this component renders while unauthenticated —
 * produced a render/navigate feedback loop severe enough to exhaust the test process's heap.
 * `handleSwitchCompany` only needs the pathname at the moment of the switch, not a live
 * subscription to it, so the non-reactive read is both correct and the fix. */
export function GuardedRoot({ children }: { children?: ReactNode }) {
  const { isAuthenticated } = useShellSession();
  const { activeCompanyId, setActiveCompanyId } = useCompanyContext();
  const navState = useNavState(isAuthenticated, activeCompanyId);
  const router = useRouter();

  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  function handleSwitchCompany(companyId: string): void {
    setActiveCompanyId(companyId);
    const pathname = router.state.location.pathname;
    const destination = getCompanySwitchDestination(pathname, companyId);
    if (destination !== pathname) {
      void router.navigate({ href: destination });
    }
  }

  return (
    <AppShell
      navEntries={navState.entries}
      navReady={navState.ready}
      navUnavailable={navState.unavailable}
      companySwitcher={{ companies: navState.companies, activeCompanyId, onSwitch: handleSwitchCompany }}
    >
      {children ?? <Outlet />}
    </AppShell>
  );
}
