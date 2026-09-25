// SPDX-License-Identifier: Apache-2.0

// React binding over the SDK's SessionContext (`activeCompanyId` — the company switcher is fed by
// org.meCompanies + the SDK session context, with path-preserving switches). Same shape as
// auth/session-context.tsx: the SDK's own context
// object is a plain synchronous-getter + subscribe API (no React dependency); this
// module supplies the "re-render on change" piece a React host needs.
import { createSessionContext, type SessionContext } from "@rosschiu/kiban-sdk";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

let cached: SessionContext | null = null;

/** Lazily builds (and memoizes) the shared SDK session-context instance — same pattern as
 * auth/sdk.ts's `getShellSdk`, usable standalone outside `<CompanyContextProvider>` (e.g. in
 * nav-state.ts's fetch hook, which is deliberately provider-free — see module-access.ts's own
 * doc comment). Exported (not module-private) so auth/session-context.tsx's logout() can clear
 * this same instance (logout must reset activeCompanyId/preferences, not just tokens) —
 * clearing any other instance would leave this one's React subscribers (CompanyContextProvider)
 * unaware, since the SDK's SessionContext notifies only its own in-process subscribers. */
export function getCompanySessionContext(): SessionContext {
  if (!cached) cached = createSessionContext();
  return cached;
}

interface CompanyContextValue {
  activeCompanyId: string | null;
  setActiveCompanyId: (companyId: string | null) => void;
}

const CompanyContext = createContext<CompanyContextValue | null>(null);

/** Wraps the SDK session context in React state, re-rendering every subscriber whenever
 * `setActiveCompanyId` is called anywhere (including from outside React, per the SDK's own
 * subscribe contract). Mounted once in app.tsx, alongside `<ShellSessionProvider>`. */
export function CompanyContextProvider({ children }: { children: ReactNode }) {
  const sessionContext = useMemo(() => getCompanySessionContext(), []);
  const [activeCompanyId, setActiveCompanyIdState] = useState<string | null>(() => sessionContext.getActiveCompanyId());

  useEffect(
    () => sessionContext.subscribe(() => setActiveCompanyIdState(sessionContext.getActiveCompanyId())),
    [sessionContext]
  );

  const value = useMemo<CompanyContextValue>(
    () => ({
      activeCompanyId,
      setActiveCompanyId: (companyId) => sessionContext.setActiveCompanyId(companyId)
    }),
    [activeCompanyId, sessionContext]
  );

  return <CompanyContext.Provider value={value}>{children}</CompanyContext.Provider>;
}

/** The reactive form — re-renders when the active company changes. Throws outside the provider
 * (same contract as `useShellSession`), since callers that mutate the active company (the
 * company switcher) need the re-render guarantee. */
export function useCompanyContext(): CompanyContextValue {
  const ctx = useContext(CompanyContext);
  if (!ctx) {
    throw new Error("useCompanyContext() called outside <CompanyContextProvider>");
  }
  return ctx;
}
