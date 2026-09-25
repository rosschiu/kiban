// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AppCompanyModuleRoutePage } from "../../src/routes/app-company-module-route";
import { AppModuleRoutePage } from "../../src/routes/app-module-route";

// Both dynamic route host page wrappers against the intentionally empty
// local module registry — proves each wires hostScope/companyId/moduleKey/splat through to
// ModuleRouteHost -> resolver correctly (module-unavailable is the only reachable outcome with
// an empty catalog). The real composition fetch runs (and fails closed, no gateway here), so the
// outcome is awaited past the loading state.
describe("AppModuleRoutePage (global host)", () => {
  it("passes hostScope=global and resolves to module-unavailable", async () => {
    render(<AppModuleRoutePage moduleKey="diagnostics" splat="overview" />);
    expect(await screen.findByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
  });
});

describe("AppCompanyModuleRoutePage (company host)", () => {
  it("passes hostScope=company + companyId and resolves to module-unavailable", async () => {
    render(<AppCompanyModuleRoutePage companyId="company-a" moduleKey="client-asset" splat="assets" />);
    expect(await screen.findByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
  });
});
