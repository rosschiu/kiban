// SPDX-License-Identifier: Apache-2.0

// React binding over the SDK's Session: login redirect, /callback completion, guarded root,
// logout. The SDK session object itself has no subscribe/notify (it's a plain
// synchronous-getter API) — this context supplies the "re-render on
// auth change" piece a React host needs, via a version counter bumped after every state-changing
// call.
import type { ApiClient, Session } from "@rosschiu/kiban-sdk";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getCompanySessionContext } from "../nav/company-context";
import { invalidatePlatformComposition } from "../nav/module-access";
import { getShellSdk, onShellSessionInvalidated } from "./sdk";

export interface ShellSession {
  session: Session;
  apiClient: ApiClient;
  isAuthenticated: boolean;
  accessToken: string | null;
  /** Redirects to Keycloak login. */
  login: () => Promise<void>;
  /** Completes the OIDC callback for the given callback URL, updates auth state, and returns the
   * resolved token set. Throws on failure (invalid state, missing code, etc.) — callers render
   * the error, they do not need to catch-and-swallow. */
  handleCallback: (callbackUrl: string) => Promise<void>;
  /** Clears session state and redirects to RP-initiated logout. */
  logout: () => void;
}

const ShellSessionContext = createContext<ShellSession | null>(null);

export function ShellSessionProvider({ children }: { children: ReactNode }) {
  const { session, apiClient } = useMemo(() => getShellSdk(), []);
  const [version, setVersion] = useState(0);

  const login = useCallback(async () => {
    await session.login();
  }, [session]);

  const handleCallback = useCallback(
    async (callbackUrl: string) => {
      await session.handleCallback(callbackUrl);
      setVersion((v) => v + 1);
    },
    [session],
  );

  const logout = useCallback(() => {
    session.logout();
    // The shared composition cache (nav + route-host inputs) must never
    // survive an auth-state change — the next session may be a different user.
    invalidatePlatformComposition();
    // Logout must clear the app-side SessionContext (active company, preferences)
    // too, not just the OIDC tokens — otherwise the next signed-in user (or the same user's next
    // session) inherits the previous session's active company / preferences.
    getCompanySessionContext().clear();
    setVersion((v) => v + 1);
  }, [session]);

  // A mid-journey silent-refresh failure (revoked/expired refresh
  // token) clears `session`'s tokens several layers below any component that calls `logout()`
  // (see sdk.ts's `onShellSessionInvalidated` header comment for the full account, and
  // `session-expiry.spec.ts`'s "revoked
  // refresh token" case). Bumping `version` here re-runs the memo below exactly like `logout()`
  // already does, so `GuardedRoot` picks up `isAuthenticated: false` on its very next render and
  // redirects to `/login` — a clean recovery instead of a page that still looks signed in while
  // every fetch silently 401s.
  useEffect(() => onShellSessionInvalidated(() => setVersion((v) => v + 1)), []);

  const value = useMemo<ShellSession>(
    () => ({
      session,
      apiClient,
      isAuthenticated: session.isAuthenticated(),
      accessToken: session.getAccessToken(),
      login,
      handleCallback,
      logout,
    }),
    // `version` is intentionally in the dep list though unused directly — it is what forces this
    // memo to recompute (and re-read the session's synchronous getters) after a state change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [session, apiClient, login, handleCallback, logout, version],
  );

  return <ShellSessionContext.Provider value={value}>{children}</ShellSessionContext.Provider>;
}

export function useShellSession(): ShellSession {
  const ctx = useContext(ShellSessionContext);
  if (!ctx) {
    throw new Error("useShellSession() called outside <ShellSessionProvider>");
  }
  return ctx;
}
