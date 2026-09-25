// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Sidebar, SidebarContent, SidebarProvider, SidebarTrigger } from "../../src/ui/sidebar";

const useIsMobile = vi.fn(() => false);
vi.mock("../../src/hooks/use-mobile", () => ({ useIsMobile: () => useIsMobile() }));

async function renderShell() {
  const rootRoute = createRootRoute({
    component: () => (
      <SidebarProvider>
        <Sidebar collapsible="icon">
          <SidebarContent>content</SidebarContent>
        </Sidebar>
        <SidebarTrigger />
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

describe("Sidebar", () => {
  it("toggles the desktop collapse state via SidebarTrigger", async () => {
    useIsMobile.mockReturnValue(false);
    const user = userEvent.setup();
    await renderShell();
    const desktopSidebar = document.querySelector('[data-slot="sidebar"][data-state="expanded"]');
    expect(desktopSidebar).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Toggle Sidebar" }));
    expect(document.querySelector('[data-slot="sidebar"][data-state="collapsed"]')).toBeInTheDocument();
  });

  it("opens the mobile Sheet when useIsMobile() is true and the trigger is clicked", async () => {
    useIsMobile.mockReturnValue(true);
    const user = userEvent.setup();
    await renderShell();
    await user.click(screen.getByRole("button", { name: "Toggle Sidebar" }));
    expect(await screen.findByText("content")).toBeInTheDocument();
  });
});
