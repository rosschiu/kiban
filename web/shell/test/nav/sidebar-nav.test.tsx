// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SidebarNav, type SidebarNavProps } from "../../src/nav/sidebar-nav";
import { SidebarProvider } from "../../src/ui/sidebar";

// SidebarNav renders through sidebar-07's SidebarMenuButton, which requires a
// SidebarProvider ancestor (useSidebar()) — SidebarProvider itself calls useLocation(), so this
// also needs a minimal Router context, same pattern as test/routes/guarded-root.test.tsx.
async function renderSidebarNav(props: SidebarNavProps) {
  const rootRoute = createRootRoute({
    component: () => (
      <SidebarProvider>
        <SidebarNav {...props} />
      </SidebarProvider>
    ),
  });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

describe("SidebarNav", () => {
  it("renders no nav items and no <nav> element for an empty catalog", async () => {
    await renderSidebarNav({ entries: [] });

    expect(screen.queryByTestId("sidebar-nav")).not.toBeInTheDocument();
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    expect(screen.getByTestId("sidebar-nav-empty")).toBeInTheDocument();
    expect(screen.getByText("No modules installed")).toBeInTheDocument();
  });

  it("renders the no-membership empty state when the caller belongs to no company", async () => {
    await renderSidebarNav({ entries: [], hasCompanies: false });

    expect(screen.getByTestId("sidebar-nav-no-membership")).toBeInTheDocument();
    expect(screen.getByText("No company membership yet")).toBeInTheDocument();
    expect(
      screen.getByText("Your account is not a member of any company yet. Ask a company administrator to add you."),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-empty")).not.toBeInTheDocument();
    expect(screen.queryByText("No modules installed")).not.toBeInTheDocument();
  });

  it("renders the could-not-load state (not no-modules, not no-membership) when a service was unavailable", async () => {
    await renderSidebarNav({ entries: [], hasCompanies: false, unavailable: "The service is temporarily unavailable. Please try again in a moment." });

    expect(screen.getByTestId("sidebar-nav-unavailable")).toBeInTheDocument();
    expect(screen.getByText("Modules could not be loaded")).toBeInTheDocument();
    expect(screen.getByText("The service is temporarily unavailable. Please try again in a moment.")).toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-empty")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-no-membership")).not.toBeInTheDocument();
  });

  it("renders the no-modules empty state (not no-membership) when companies exist but nothing is enabled", async () => {
    await renderSidebarNav({ entries: [], hasCompanies: true });

    expect(screen.getByTestId("sidebar-nav-empty")).toBeInTheDocument();
    expect(screen.getByText("No modules installed")).toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-no-membership")).not.toBeInTheDocument();
  });

  it("renders the loading skeleton, never an empty state, while not ready even with no companies", async () => {
    await renderSidebarNav({ entries: [], ready: false, hasCompanies: false });

    expect(screen.getByTestId("sidebar-nav-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-no-membership")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sidebar-nav-empty")).not.toBeInTheDocument();
  });

  it("renders entries (never the no-membership state) when entries exist without a company", async () => {
    await renderSidebarNav({
      entries: [{ moduleKey: "admin-positions", label: "Positions", href: "/app/admin/positions" }],
      hasCompanies: false,
    });

    expect(screen.getAllByRole("link")).toHaveLength(1);
    expect(screen.queryByTestId("sidebar-nav-no-membership")).not.toBeInTheDocument();
  });

  it("renders one link per entry, in the given order, when the catalog is non-empty", async () => {
    await renderSidebarNav({
      entries: [
        { moduleKey: "diagnostics", label: "Diagnostics", href: "/app/diagnostics" },
        { moduleKey: "client-asset", label: "Client assets", href: "/app/c/company-a/client-asset" },
      ],
    });

    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveTextContent("Diagnostics");
    expect(links[0]).toHaveAttribute("href", "/app/diagnostics");
    expect(links[1]).toHaveTextContent("Client assets");
    expect(screen.queryByTestId("sidebar-nav-empty")).not.toBeInTheDocument();
  });

  it("renders an unread badge pill when an entry has a positive badge count", async () => {
    await renderSidebarNav({
      entries: [{ moduleKey: "notification", label: "Notification", href: "/app/c/company-a/notification", badge: 3 }],
    });

    expect(screen.getByTestId("nav-badge-notification")).toHaveTextContent("3");
  });

  it("caps a large badge count at 99+", async () => {
    await renderSidebarNav({
      entries: [{ moduleKey: "notification", label: "Notification", href: "/app/c/company-a/notification", badge: 150 }],
    });

    expect(screen.getByTestId("nav-badge-notification")).toHaveTextContent("99+");
  });

  it("renders no badge pill when the entry has no badge count", async () => {
    await renderSidebarNav({ entries: [{ moduleKey: "diagnostics", label: "Diagnostics", href: "/app/diagnostics" }] });

    expect(screen.queryByTestId(`nav-badge-diagnostics`)).not.toBeInTheDocument();
  });
});
