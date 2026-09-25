// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { getCompanySwitchDestination } from "../../src/nav/company-switch-path";

describe("getCompanySwitchDestination", () => {
  it("rewrites just the companyId segment on a company-scoped route, preserving the remainder", () => {
    expect(getCompanySwitchDestination("/app/c/company-a/client-asset/overview", "company-b")).toBe(
      "/app/c/company-b/client-asset/overview",
    );
  });

  it("preserves a bare company root with no remainder", () => {
    expect(getCompanySwitchDestination("/app/c/company-a", "company-b")).toBe("/app/c/company-b");
  });

  it("URI-encodes the new company id", () => {
    expect(getCompanySwitchDestination("/app/c/company-a/client-asset", "company b")).toBe(
      "/app/c/company%20b/client-asset",
    );
  });

  it("leaves a global module route unchanged (no company scope to rewrite)", () => {
    expect(getCompanySwitchDestination("/app/diagnostics/overview", "company-b")).toBe("/app/diagnostics/overview");
  });

  it("leaves the app dashboard root unchanged", () => {
    expect(getCompanySwitchDestination("/app", "company-b")).toBe("/app");
  });
});
