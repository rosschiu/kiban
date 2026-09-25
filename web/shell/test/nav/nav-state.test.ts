// SPDX-License-Identifier: Apache-2.0

import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const fetchPlatformComposition = vi.fn();
vi.mock("../../src/nav/module-access", () => ({
  fetchPlatformCompositionCached: () => fetchPlatformComposition(),
  invalidatePlatformComposition: () => {},
  getCompositionSnapshot: () => null,
}));

const registeredModule = {
  catalog: { moduleKey: "diagnostics", scope: "global" as const, routes: [] },
  nav: { label: "Diagnostics", navOrder: 10 },
  pages: {},
  // Only badges when a company is active — keeps every activeCompanyId=null test below
  // (the vast majority) unaffected; a dedicated test below exercises the merge itself.
  useUnreadCount: (companyId: string | null) => (companyId === "company-a" ? 7 : undefined),
};
vi.mock("../../src/modules/registry", () => ({ localModuleRegistry: { diagnostics: registeredModule } }));

const setActiveCompanyId = vi.fn();
vi.mock("../../src/nav/company-context", () => ({
  getCompanySessionContext: () => ({ setActiveCompanyId }),
}));

const { useNavState } = await import("../../src/nav/nav-state");

describe("useNavState", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the empty shape without fetching when unauthenticated", () => {
    const { result } = renderHook(() => useNavState(false, null));
    expect(result.current).toEqual({ entries: [], companies: [], ready: true });
    expect(fetchPlatformComposition).not.toHaveBeenCalled();
  });

  it("composes nav entries + companies once fetched, when authenticated", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [{ module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [] }],
      catalog: [
        {
          moduleKey: "diagnostics",
          displayName: "Diagnostics",
          scopeType: "global",
          mandatory: false,
          basePath: "/diagnostics",
          healthPath: "/health",
          port: 9000,
          licenseClass: "standard",
          manifestVersion: "1.0.0",
          isActive: true,
          installed: true,
          enabled: true,
        },
      ],
      globalSummary: null,
      meCompanies: [{ id: "company-a", code: "A", name: "Company A", isActive: true }],
      companySummaries: new Map(),
    });

    const { result } = renderHook(() => useNavState(true, null));
    await waitFor(() =>
      expect(result.current).toEqual({
        entries: [{ moduleKey: "diagnostics", label: "Diagnostics", href: "/app/diagnostics", icon: undefined }],
        companies: [{ id: "company-a", code: "A", name: "Company A", isActive: true }],
        ready: true,
      }),
    );
  });

  it("passes the composition's `unavailable` message through for the sidebar", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [],
      catalog: [],
      globalSummary: null,
      meCompanies: [],
      companySummaries: new Map(),
      unavailable: "Could not reach the server. Check your connection and try again.",
    });
    const { result } = renderHook(() => useNavState(true, null));
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.unavailable).toBe("Could not reach the server. Check your connection and try again.");
  });

  it("fails closed to the empty shape when the fetch rejects", async () => {
    fetchPlatformComposition.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useNavState(true, null));
    await waitFor(() => expect(result.current).toEqual({ entries: [], companies: [], ready: true }));
  });

  it("merges an unread badge onto the matching entry when the registered module supplies one", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [{ module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [] }],
      catalog: [
        {
          moduleKey: "diagnostics",
          displayName: "Diagnostics",
          scopeType: "global",
          mandatory: false,
          basePath: "/diagnostics",
          healthPath: "/health",
          port: 9000,
          licenseClass: "standard",
          manifestVersion: "1.0.0",
          isActive: true,
          installed: true,
          enabled: true,
        },
      ],
      globalSummary: null,
      meCompanies: [],
      companySummaries: new Map(),
    });

    const { result } = renderHook(() => useNavState(true, "company-a"));
    await waitFor(() => expect(result.current.entries[0]?.badge).toBe(7));
  });

  it("omits the badge field when the registered module's hook returns undefined", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [{ module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [] }],
      catalog: [
        {
          moduleKey: "diagnostics",
          displayName: "Diagnostics",
          scopeType: "global",
          mandatory: false,
          basePath: "/diagnostics",
          healthPath: "/health",
          port: 9000,
          licenseClass: "standard",
          manifestVersion: "1.0.0",
          isActive: true,
          installed: true,
          enabled: true,
        },
      ],
      globalSummary: null,
      meCompanies: [],
      companySummaries: new Map(),
    });

    const { result } = renderHook(() => useNavState(true, null));
    await waitFor(() => expect(result.current.entries).toHaveLength(1));
    expect(result.current.entries[0]).not.toHaveProperty("badge");
  });

  it("clears a persisted activeCompanyId the caller no longer belongs to (stale-selection reconcile)", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [],
      catalog: [],
      globalSummary: null,
      meCompanies: [{ id: "company-a", code: "A", name: "Company A", isActive: true }],
      companySummaries: new Map(),
    });
    renderHook(() => useNavState(true, "deleted-company"));
    await waitFor(() => expect(setActiveCompanyId).toHaveBeenCalledWith(null));
  });

  it("keeps the selection when it matches a reported membership", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [],
      catalog: [],
      globalSummary: null,
      meCompanies: [{ id: "company-a", code: "A", name: "Company A", isActive: true }],
      companySummaries: new Map(),
    });
    const { result } = renderHook(() => useNavState(true, "company-a"));
    await waitFor(() => expect(result.current.companies).toHaveLength(1));
    expect(setActiveCompanyId).not.toHaveBeenCalled();
  });

  it("does NOT clear the selection on an empty companies list (fail-closed fetch must not drop a valid selection)", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [],
      catalog: [],
      globalSummary: null,
      meCompanies: [],
      companySummaries: new Map(),
    });
    const { result } = renderHook(() => useNavState(true, "company-a"));
    await waitFor(() => expect(fetchPlatformComposition).toHaveBeenCalled());
    await waitFor(() => expect(result.current.entries).toBeDefined());
    expect(setActiveCompanyId).not.toHaveBeenCalled();
  });

  it("re-fetches when activeCompanyId changes", async () => {
    fetchPlatformComposition.mockResolvedValue({
      capabilities: [],
      catalog: [],
      globalSummary: null,
      meCompanies: [],
      companySummaries: new Map(),
    });
    const { rerender } = renderHook(({ companyId }) => useNavState(true, companyId), { initialProps: { companyId: null as string | null } });
    await waitFor(() => expect(fetchPlatformComposition).toHaveBeenCalledTimes(1));
    rerender({ companyId: "company-a" });
    await waitFor(() => expect(fetchPlatformComposition).toHaveBeenCalledTimes(2));
  });
});
