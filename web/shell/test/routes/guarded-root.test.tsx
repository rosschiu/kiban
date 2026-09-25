// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GuardedRoot } from "../../src/routes/guarded-root";

const useShellSession = vi.fn();
vi.mock("../../src/auth/session-context", () => ({ useShellSession: () => useShellSession() }));

const setActiveCompanyId = vi.fn();
const useCompanyContext = vi.fn();
vi.mock("../../src/nav/company-context", () => ({ useCompanyContext: () => useCompanyContext() }));

const useNavState = vi.fn();
vi.mock("../../src/nav/nav-state", () => ({ useNavState: (...args: unknown[]) => useNavState(...args) }));

async function renderAt(initialPath: string) {
  const rootRoute = createRootRoute();
  const guardedRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/app",
    component: () => <GuardedRoot>guarded content</GuardedRoot>,
  });
  // Company-scoped catch-all child so a path like /app/c/company-a/client-asset/overview
  // resolves without a 404 — the child's own component never renders (GuardedRoot ignores
  // <Outlet/> here, passing explicit children instead), only its path needs to match for
  // router.navigate assertions. Scoped under `c/$companyId` (not a bare `$`) so it never
  // ambiguously matches the plain `/app` root itself.
  const catchAllRoute = createRoute({
    getParentRoute: () => guardedRoute,
    path: "c/$companyId/$",
    component: () => null,
  });
  const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", component: () => <div>login page</div> });
  const routeTree = rootRoute.addChildren([guardedRoute.addChildren([catchAllRoute]), loginRoute]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initialPath] }) });
  // Wrap render()+load() in one act() so route-match resolution (an async React state update)
  // is treated as a single flushed batch instead of warning about updates outside act()
  // (same fix as test/routes/callback.test.tsx).
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
  return router;
}

describe("GuardedRoot", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useCompanyContext.mockReturnValue({ activeCompanyId: null, setActiveCompanyId });
    useNavState.mockReturnValue({ entries: [], companies: [] });
  });

  it("redirects to /login when unauthenticated, rendering no app chrome", async () => {
    useShellSession.mockReturnValue({ isAuthenticated: false, logout: vi.fn() });
    await renderAt("/app");
    expect(await screen.findByText("login page")).toBeInTheDocument();
    expect(screen.queryByText("guarded content")).not.toBeInTheDocument();
  });

  it("renders the AppShell + children when authenticated", async () => {
    useShellSession.mockReturnValue({ isAuthenticated: true, logout: vi.fn(), session: { getTokens: () => null } });
    await renderAt("/app");
    expect(await screen.findByText("guarded content")).toBeInTheDocument();
    expect(screen.getByText("Kiban")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /log out/i })).toBeInTheDocument();
  });

  it("passes useNavState's entries through to the sidebar", async () => {
    useShellSession.mockReturnValue({ isAuthenticated: true, logout: vi.fn(), session: { getTokens: () => null } });
    useNavState.mockReturnValue({
      entries: [{ moduleKey: "diagnostics", label: "Diagnostics", href: "/app/diagnostics" }],
      companies: [],
    });
    await renderAt("/app");
    expect(await screen.findByRole("link", { name: "Diagnostics" })).toBeInTheDocument();
  });

  it("renders the company switcher and switches company + rewrites a company-scoped path", async () => {
    useShellSession.mockReturnValue({ isAuthenticated: true, logout: vi.fn(), session: { getTokens: () => null } });
    useCompanyContext.mockReturnValue({ activeCompanyId: "company-a", setActiveCompanyId });
    useNavState.mockReturnValue({
      entries: [],
      companies: [
        { id: "company-a", code: "A", name: "Company A", isActive: true },
        { id: "company-b", code: "B", name: "Company B", isActive: true },
      ],
    });
    const router = await renderAt("/app/c/company-a/client-asset/overview");
    const user = userEvent.setup();

    const select = screen.getByTestId("company-switcher-select");
    await user.selectOptions(select, "company-b");

    expect(setActiveCompanyId).toHaveBeenCalledWith("company-b");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/app/c/company-b/client-asset/overview");
    });
  });

  it("does not navigate when switching company on a non-company-scoped path", async () => {
    useShellSession.mockReturnValue({ isAuthenticated: true, logout: vi.fn(), session: { getTokens: () => null } });
    useCompanyContext.mockReturnValue({ activeCompanyId: "company-a", setActiveCompanyId });
    useNavState.mockReturnValue({
      entries: [],
      companies: [
        { id: "company-a", code: "A", name: "Company A", isActive: true },
        { id: "company-b", code: "B", name: "Company B", isActive: true },
      ],
    });
    const router = await renderAt("/app");
    const user = userEvent.setup();

    const select = screen.getByTestId("company-switcher-select");
    await user.selectOptions(select, "company-b");

    expect(setActiveCompanyId).toHaveBeenCalledWith("company-b");
    expect(router.state.location.pathname).toBe("/app");
  });
});
