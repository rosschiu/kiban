// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "../../src/ui/app-shell";

const useShellSession = vi.fn();
vi.mock("../../src/auth/session-context", () => ({ useShellSession: () => useShellSession() }));

// AppShell renders through shadcn's sidebar-07 primitives, which call
// useLocation()/useNavigate() internally (SidebarProvider's mobile-auto-close effect, the
// active-nav-item highlight) — it now needs a Router context to render at all, same as
// test/routes/guarded-root.test.tsx's own renderAt() helper.
async function renderAppShell(children: React.ReactNode, props: Omit<Parameters<typeof AppShell>[0], "children"> = {}) {
  const rootRoute = createRootRoute({ component: () => <AppShell {...props}>{children}</AppShell> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

function mockSession(overrides: Partial<ReturnType<typeof useShellSession>> = {}) {
  useShellSession.mockReturnValue({
    logout: vi.fn(),
    session: { getTokens: () => null },
    ...overrides,
  });
}

describe("AppShell", () => {
  it("shows the empty-nav state when navEntries is omitted (default empty catalog)", async () => {
    mockSession();
    await renderAppShell("content");
    expect(screen.getByTestId("sidebar-nav-empty")).toBeInTheDocument();
    expect(screen.getByText("content")).toBeInTheDocument();
  });

  it("wires the logout button to session.logout()", async () => {
    const logout = vi.fn();
    mockSession({ logout });
    const user = userEvent.setup();
    await renderAppShell("content");
    await user.click(screen.getByRole("button", { name: /log out/i }));
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it("renders no company switcher when the prop is omitted", async () => {
    mockSession();
    await renderAppShell("content");
    expect(screen.queryByTestId("company-switcher")).not.toBeInTheDocument();
  });

  it("renders the company switcher when companies are present", async () => {
    mockSession();
    await renderAppShell("content", {
      companySwitcher: {
        companies: [{ id: "company-a", code: "A", name: "Company A", isActive: true }],
        activeCompanyId: "company-a",
        onSwitch: vi.fn(),
      },
    });
    expect(screen.getByTestId("company-switcher")).toBeInTheDocument();
  });
});
