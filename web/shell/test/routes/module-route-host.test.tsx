// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ModuleRouteHost } from "../../src/routes/module-route-host";
import { emptyModuleAccess } from "../../src/nav/compose";

const useModuleAccess = vi.fn(() => emptyModuleAccess);
// ready defaults true — most tests assert RESOLVED outcomes; the loading-gate test flips it.
const accessReady = vi.fn(() => true);
vi.mock("../../src/nav/module-access", () => ({ useModuleAccess: () => ({ access: useModuleAccess(), ready: accessReady() }) }));

const request = vi.fn().mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 });
vi.mock("../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

// With an empty local module registry every request resolves to module-unavailable, regardless
// of hostScope/companyId — proving the resolver is wired for real, not stubbed to always say
// "ready" (`useModuleAccess` defaults to the empty shape). A second describe block below
// registers the notification module to exercise the "ready" outcome.
describe("ModuleRouteHost while the composition is still loading (checkpoint-6)", () => {
  it("renders the neutral loading state, never a terminal outcome, before the composition resolves", () => {
    accessReady.mockReturnValueOnce(false);
    render(<ModuleRouteHost hostScope="global" moduleKey="diagnostics" modulePath="/overview" />);
    expect(screen.getByTestId("module-loading")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Module unavailable" })).not.toBeInTheDocument();
  });
});

describe("ModuleRouteHost against an unreachable module (module-unavailable outcomes)", () => {
  it("resolves an unknown module on the global host to module-unavailable", () => {
    render(<ModuleRouteHost hostScope="global" moduleKey="diagnostics" modulePath="/overview" />);
    expect(screen.getByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
    expect(screen.getByText("diagnostics")).toBeInTheDocument();
  });

  it("resolves an unknown module on the company host to module-unavailable", () => {
    render(<ModuleRouteHost hostScope="company" companyId="company-a" moduleKey="client-asset" modulePath="/assets" />);
    expect(screen.getByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
    expect(screen.getByText("client-asset")).toBeInTheDocument();
  });

  it("resolves the real, registered notification module to module-unavailable when access excludes it (module-disabled proof)", () => {
    // Same as the two cases above, but against a moduleKey that IS registered — proves a
    // disabled/uninstalled notification module renders the shell's designed state, not the
    // module's own page.
    render(<ModuleRouteHost hostScope="company" companyId="company-a" moduleKey="notification" modulePath="/" />);
    expect(screen.getByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
    expect(screen.getByText("notification")).toBeInTheDocument();
  });
});

describe("ModuleRouteHost against the real notification module (ready outcome)", () => {
  it("renders the notification module's inbox page when access grants it", async () => {
    useModuleAccess.mockReturnValue({
      availableModuleKeys: ["notification"],
      globalFeatureKeys: [],
      moduleKeysByCompany: { "company-a": ["notification"] },
      featureKeysByCompany: { "company-a": ["notification.access"] },
    });

    render(<ModuleRouteHost hostScope="company" companyId="company-a" moduleKey="notification" modulePath="/" />);

    await waitFor(() => expect(screen.getByTestId("notification-inbox-page")).toBeInTheDocument());
    useModuleAccess.mockReturnValue(emptyModuleAccess);
  });
});
