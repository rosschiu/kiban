// SPDX-License-Identifier: Apache-2.0

import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const withBadge = {
  catalog: { moduleKey: "notification", scope: "company" as const, routes: [] },
  nav: { label: "Notification", navOrder: 10 },
  pages: {},
  useUnreadCount: (companyId: string | null) => (companyId ? 3 : undefined),
};
const withZeroBadge = {
  catalog: { moduleKey: "zero", scope: "company" as const, routes: [] },
  nav: { label: "Zero", navOrder: 20 },
  pages: {},
  useUnreadCount: () => 0,
};
const withoutBadge = {
  catalog: { moduleKey: "diagnostics", scope: "global" as const, routes: [] },
  nav: { label: "Diagnostics", navOrder: 30 },
  pages: {},
};

vi.mock("../../src/modules/registry", () => ({
  localModuleRegistry: { notification: withBadge, zero: withZeroBadge, diagnostics: withoutBadge },
}));

const { useNavBadges } = await import("../../src/nav/nav-badges");

describe("useNavBadges", () => {
  it("includes only modules whose useUnreadCount returns a positive number", () => {
    const { result } = renderHook(() => useNavBadges("company-a"));
    expect(result.current).toEqual({ notification: 3 });
  });

  it("returns an empty map when there is no active company", () => {
    const { result } = renderHook(() => useNavBadges(null));
    expect(result.current).toEqual({});
  });
});
