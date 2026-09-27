// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CallbackPage } from "../../src/routes/callback";

const useShellSession = vi.fn();
vi.mock("../../src/auth/session-context", () => ({ useShellSession: () => useShellSession() }));

async function renderAt(initialPath: string) {
  const rootRoute = createRootRoute();
  const callbackRoute = createRoute({ getParentRoute: () => rootRoute, path: "/callback", component: CallbackPage });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: "/app", component: () => <div>app landing</div> });
  const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => <div>root landing</div> });
  const routeTree = rootRoute.addChildren([callbackRoute, appRoute, indexRoute]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initialPath] }) });
  // Router loading/rendering triggers React state updates (route matches resolving
  // asynchronously); wrap both render() and load() in the same act() so RTL treats it as one
  // flushed batch instead of warning about updates outside act().
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
  return router;
}

const signedOut = { isAuthenticated: () => false };

describe("CallbackPage", () => {
  beforeEach(() => {
    vi.stubGlobal("location", { ...window.location, href: "https://app.invalid/callback?code=abc&state=xyz", search: "?code=abc&state=xyz" });
  });

  it("shows an error alert when handleCallback rejects and nobody is signed in", async () => {
    useShellSession.mockReturnValue({ handleCallback: vi.fn().mockRejectedValue(new Error("bad state")), session: signedOut });
    await renderAt("/callback?code=abc&state=xyz");
    expect(await screen.findByText("Sign in failed")).toBeInTheDocument();
    expect(screen.getByText("bad state")).toBeInTheDocument();
  });

  it("navigates to /app on a successful callback with no returnPath, replacing the callback history entry", async () => {
    useShellSession.mockReturnValue({ handleCallback: vi.fn().mockResolvedValue(undefined), session: signedOut });
    const router = await renderAt("/callback?code=abc&state=xyz");
    expect(await screen.findByText("app landing")).toBeInTheDocument();
    // `replace`: the consumed /callback?code=… URL is gone from history (a push would leave it
    // one Back away, and a reload of it re-runs a spent code).
    expect(router.history.length).toBe(1);
  });

  // A hard reload of `/callback?code=…` after the exchange already succeeded: the code is spent
  // and the PKCE transaction gone (handleCallback rejects), but the persisted session is live —
  // that is a signed-in user, not a failed sign-in.
  it("redirects to /app instead of showing an error when handleCallback rejects but the session is already authenticated", async () => {
    useShellSession.mockReturnValue({
      handleCallback: vi.fn().mockRejectedValue(new Error("No pending OIDC transaction found")),
      session: { isAuthenticated: () => true },
    });
    await renderAt("/callback?code=abc&state=xyz");
    expect(await screen.findByText("app landing")).toBeInTheDocument();
    expect(screen.queryByText("Sign in failed")).not.toBeInTheDocument();
  });

  // `/callback` with neither `code` nor `error` (e.g. an old bookmark, a stray direct
  // navigation, or a Keycloak logout redirect) must redirect to `/` instead
  // of invoking handleCallback() and surfacing its "missing code and/or state" error.
  it("redirects to / and never calls handleCallback when neither code nor error is present", async () => {
    vi.stubGlobal("location", { ...window.location, href: "https://app.invalid/callback", search: "" });
    const handleCallback = vi.fn();
    useShellSession.mockReturnValue({ handleCallback, session: signedOut });

    await renderAt("/callback");

    expect(await screen.findByText("root landing")).toBeInTheDocument();
    expect(handleCallback).not.toHaveBeenCalled();
  });

  it("does not redirect to / when an error param is present (still handles it via handleCallback)", async () => {
    vi.stubGlobal("location", {
      ...window.location,
      href: "https://app.invalid/callback?error=access_denied",
      search: "?error=access_denied",
    });
    useShellSession.mockReturnValue({ handleCallback: vi.fn().mockRejectedValue(new Error("access_denied")), session: signedOut });

    await renderAt("/callback?error=access_denied");

    expect(await screen.findByText("Sign in failed")).toBeInTheDocument();
  });
});
