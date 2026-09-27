// SPDX-License-Identifier: Apache-2.0

// The shell's one instance of the SDK session + API client (all API access goes through the SDK,
// never direct fetch). Built once at module load from readShellEnv() so every consumer (session
// context, route loaders, nav composition) shares the same session/refresh state.
import { createApiClient, createSession, type ApiClient, type Session } from "@rosschiu/kiban-sdk";
import { readShellEnv } from "../lib/env";

let cached: { session: Session; apiClient: ApiClient } | null = null;

// Session-invalidation listeners: the SDK's Session has no subscribe/notify by design (see auth/
// session-context.tsx's header comment). That's fine for state changes this shell already routes
// through `ShellSessionProvider`'s own `login`/`handleCallback`/`logout` calls (each bumps
// `version` itself) — but a MID-JOURNEY silent-refresh failure (the refresh token was
// revoked/expired server-side; covered by `web/shell/e2e/session-expiry.spec.ts`'s "revoked
// refresh token" case) happens entirely inside `apiClient`'s own 401 handler, several layers
// below any component that could call `logout()`. `session.refresh()` clears the session's
// tokens internally on an IdP rejection, but nothing would tell React — `isAuthenticated` would
// stay frozen at its last `version`-bumped value, so `GuardedRoot` would never redirect to
// `/login`, leaving the caller looking signed in while every module fetch silently failed closed.
// So, entirely within the shell (never touching the SDK's own Session contract): a tiny listener
// set that `refreshAccessToken` notifies only on the specific transition that matters (refresh
// failed AND the session is now actually gone) — `session-context.tsx` subscribes once and bumps
// its own `version`, the same mechanism `logout()` already uses.
type AuthChangeListener = () => void;
const authChangeListeners = new Set<AuthChangeListener>();

/** Subscribe to "the session was cleared by something other than an explicit logout() call"
 * (currently: a failed mid-journey silent refresh). Returns an unsubscribe function. */
export function onShellSessionInvalidated(listener: AuthChangeListener): () => void {
  authChangeListeners.add(listener);
  return () => authChangeListeners.delete(listener);
}

/** Lazily builds (and memoizes) the shared session + API client. Lazy so tests can stub
 * `import.meta.env`/`window` before first use without a module-load-time side effect. */
export function getShellSdk(): { session: Session; apiClient: ApiClient } {
  if (cached) return cached;

  const env = readShellEnv();
  const session = createSession({
    authOrigin: env.gatewayOrigin,
    realm: env.realm,
    clientId: env.clientId,
    redirectUri: env.redirectUri,
    // persistTokens: the SDK's own default (false, "the safer default", auth/session.ts) keeps
    // tokens in memory only — which does not survive a full page navigation. The shell's dynamic
    // route-host design (module-route-host.tsx) is built around a user landing on a direct URL
    // (a bookmark, a shared link, a browser refresh) and staying signed in; memory-only tokens
    // would log the user out on every such navigation (`GuardedRoot` redirects to `/login`).
    // sessionStorage (not localStorage — the SDK's persisted-token storage is always
    // sessionStorage, auth/session.ts) still clears on tab close.
    persistTokens: true,
  });
  const apiClient = createApiClient({
    baseUrl: env.gatewayOrigin,
    getAccessToken: () => session.getAccessToken(),
    getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
    refreshAccessToken: async () => {
      const wasAuthenticated = session.isAuthenticated();
      const newToken = await session.refresh();
      // Only the "was signed in, refresh() concluded the session is genuinely gone" transition
      // is notified — a refresh that fails for a transient network reason leaves session state
      // (including the refresh token) intact per `Session.refresh()`'s own contract, so
      // `session.isAuthenticated()` still reads however the CURRENT (unexpired-until-then)
      // access token says it does; nothing to notify, and no spurious redirect on a blip.
      if (wasAuthenticated && !newToken && !session.isAuthenticated()) {
        for (const listener of authChangeListeners) listener();
      }
      return newToken;
    },
  });

  cached = { session, apiClient };
  return cached;
}
