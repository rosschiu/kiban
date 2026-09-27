// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AccessDeniedState, ModuleErrorState, ModuleUnavailableState, RouteNotFoundState } from "../../src/routes/states";

describe("the four designed module-route failure states", () => {
  it("module-unavailable names the module and is visually distinct from the other three", () => {
    render(<ModuleUnavailableState moduleKey="client-asset" />);
    expect(screen.getByRole("heading", { name: "Module unavailable" })).toBeInTheDocument();
    expect(screen.getByText("client-asset")).toBeInTheDocument();
  });

  it("route-not-found names the module and the unmatched path", () => {
    render(<RouteNotFoundState moduleKey="client-asset" modulePath="/unknown" />);
    expect(screen.getByRole("heading", { name: "Page not found in this module" })).toBeInTheDocument();
    expect(screen.getByText("/unknown")).toBeInTheDocument();
  });

  it("access-denied names the missing feature key", () => {
    render(<AccessDeniedState moduleKey="client-asset" featureKey="client-asset.assets.edit" />);
    expect(screen.getByRole("heading", { name: "Access denied" })).toBeInTheDocument();
    expect(screen.getByText("client-asset.assets.edit")).toBeInTheDocument();
  });

  it("module-error offers a retry action distinct from the other three (no action)", () => {
    const onRetry = vi.fn();
    render(<ModuleErrorState moduleKey="client-asset" onRetry={onRetry} />);
    expect(screen.getByRole("heading", { name: "Module failed to load" })).toBeInTheDocument();
    screen.getByRole("button", { name: "Try again" }).click();
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
