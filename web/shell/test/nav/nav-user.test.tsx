// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { NavUser } from "../../src/nav/nav-user";
import { SidebarProvider } from "../../src/ui/sidebar";

async function renderNavUser(onSignOut = vi.fn()) {
  const rootRoute = createRootRoute({
    component: () => (
      <SidebarProvider>
        <NavUser user={{ name: "Kiban Superadmin", email: "superadmin@kiban.local", avatar: null }} onSignOut={onSignOut} />
      </SidebarProvider>
    ),
  });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
  return onSignOut;
}

describe("NavUser", () => {
  it("shows the user's name and email on the trigger", async () => {
    await renderNavUser();
    expect(screen.getAllByText("Kiban Superadmin")[0]).toBeInTheDocument();
    expect(screen.getAllByText("superadmin@kiban.local")[0]).toBeInTheDocument();
  });

  it("opens the dropdown and calls onSignOut when Log out is selected", async () => {
    const onSignOut = await renderNavUser();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /kiban superadmin/i }));
    const logOutItem = await screen.findByText("Log out");
    await user.click(logOutItem);
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });
});
