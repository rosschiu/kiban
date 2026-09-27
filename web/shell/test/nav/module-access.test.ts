// SPDX-License-Identifier: Apache-2.0

import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const listCapabilities = vi.fn();
const getCatalog = vi.fn();
const getSummary = vi.fn();
const getMeCompanies = vi.fn();

vi.mock("@rosschiu/kiban-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@rosschiu/kiban-sdk")>()),
  createCapabilitiesClient: () => ({ list: listCapabilities }),
  createSuperadminClient: () => ({ catalog: getCatalog }),
  createEffectiveAccessClient: () => ({ summary: getSummary }),
  createOrgClient: () => ({ meCompanies: getMeCompanies }),
}));

const isAuthenticated = vi.fn();
vi.mock("../../src/auth/sdk", () => ({
  getShellSdk: () => ({ session: { isAuthenticated }, apiClient: { baseUrl: "https://gateway.invalid", request: vi.fn() } }),
}));

const { fetchPlatformCompositionCached, useModuleAccess, invalidatePlatformComposition } = await import("../../src/nav/module-access");
const { emptyModuleAccess } = await import("../../src/nav/compose");

describe("fetchPlatformCompositionCached (the underlying composition fetch)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidatePlatformComposition();
  });

  it("fetches one summary per meCompanies entry, keyed by company id", async () => {
    listCapabilities.mockResolvedValue([]);
    getCatalog.mockResolvedValue([]);
    getSummary.mockImplementation((companyId?: string) =>
      Promise.resolve({
        apiVersion: 1,
        subjectId: "user-1",
        companyId: companyId ?? "",
        moduleKey: "",
        featureKeys: companyId ? [`${companyId}.feature`] : ["global.feature"],
        roleBindings: [],
        objectAccess: [],
        rowScopes: [],
        fieldPolicies: [],
      }),
    );
    getMeCompanies.mockResolvedValue([
      { id: "company-a", code: "A", name: "Company A", isActive: true },
      { id: "company-b", code: "B", name: "Company B", isActive: true },
    ]);

    const data = await fetchPlatformCompositionCached();

    expect(getSummary).toHaveBeenCalledWith();
    expect(getSummary).toHaveBeenCalledWith("company-a");
    expect(getSummary).toHaveBeenCalledWith("company-b");
    expect(data.globalSummary?.featureKeys).toEqual(["global.feature"]);
    expect(data.companySummaries.get("company-a")?.featureKeys).toEqual(["company-a.feature"]);
    expect(data.companySummaries.get("company-b")?.featureKeys).toEqual(["company-b.feature"]);
  });

  it("fails closed to empty/null on any leaf rejection, never throwing", async () => {
    listCapabilities.mockRejectedValue(new Error("boom"));
    getCatalog.mockRejectedValue(new Error("boom"));
    getSummary.mockRejectedValue(new Error("boom"));
    getMeCompanies.mockRejectedValue(new Error("boom"));

    const data = await fetchPlatformCompositionCached();

    expect(data.capabilities).toEqual([]);
    expect(data.catalog).toEqual([]);
    expect(data.globalSummary).toBeNull();
    expect(data.meCompanies).toEqual([]);
    expect(data.companySummaries.size).toBe(0);
  });
});

describe("useModuleAccess", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // the composition is session-persistent module state now — isolate each test
    invalidatePlatformComposition();
  });

  it("never consults the session itself: with a resolved snapshot and an expired token it keeps the real access data (GuardedRoot is the one auth gate)", async () => {
    isAuthenticated.mockReturnValue(true);
    listCapabilities.mockResolvedValue([{ module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [] }]);
    getCatalog.mockResolvedValue([
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
    ]);
    getSummary.mockResolvedValue(null);
    getMeCompanies.mockResolvedValue([]);
    await fetchPlatformCompositionCached();

    // The access token passed expiry between the fetch and this mount (the pre-fix live read
    // degraded the hook to the empty shape here → "Module unavailable").
    isAuthenticated.mockReturnValue(false);
    const { result } = renderHook(() => useModuleAccess());

    expect(result.current.ready).toBe(true);
    expect(result.current.access.availableModuleKeys).toEqual(["diagnostics"]);
    expect(isAuthenticated).not.toHaveBeenCalled();
  });

  it("records a service failure (5xx) as `unavailable` on the composition, but not a 403", async () => {
    const { KibanApiError } = await import("@rosschiu/kiban-sdk");
    listCapabilities.mockRejectedValue(new KibanApiError(503, "AUTHORIZATION_UNAVAILABLE", "authz down"));
    getCatalog.mockResolvedValue([]);
    getSummary.mockRejectedValue(new KibanApiError(403, "AUTHORIZATION_DENIED", "no"));
    getMeCompanies.mockResolvedValue([]);

    const data = await fetchPlatformCompositionCached();
    expect(data.unavailable).toBe("The service is temporarily unavailable. Please try again in a moment.");

    invalidatePlatformComposition();
    listCapabilities.mockRejectedValue(new KibanApiError(403, "AUTHORIZATION_DENIED", "no"));
    expect((await fetchPlatformCompositionCached()).unavailable).toBeNull();
  });

  it("returns real access data once fetched, when authenticated", async () => {
    isAuthenticated.mockReturnValue(true);
    listCapabilities.mockResolvedValue([{ module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [] }]);
    getCatalog.mockResolvedValue([
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
    ]);
    getSummary.mockResolvedValue({
      apiVersion: 1,
      subjectId: "user-1",
      companyId: "",
      moduleKey: "",
      featureKeys: [],
      roleBindings: [],
      objectAccess: [],
      rowScopes: [],
      fieldPolicies: [],
    });
    getMeCompanies.mockResolvedValue([]);

    const { result } = renderHook(() => useModuleAccess());
    await waitFor(() => expect(result.current.access.availableModuleKeys).toEqual(["diagnostics"]));
    expect(result.current.ready).toBe(true);
  });

  it("fails closed to the empty shape when the fetch rejects outright", async () => {
    isAuthenticated.mockReturnValue(true);
    listCapabilities.mockRejectedValue(new Error("network down"));
    getCatalog.mockRejectedValue(new Error("network down"));
    getSummary.mockRejectedValue(new Error("network down"));
    getMeCompanies.mockRejectedValue(new Error("network down"));

    const { result } = renderHook(() => useModuleAccess());
    // leaf failures are caught per-leaf, so the composition resolves (degraded) — ready with
    // the empty shape either way
    await waitFor(() => expect(result.current.access).toEqual(emptyModuleAccess));
    await waitFor(() => expect(result.current.ready).toBe(true));
  });

  it("discards a late resolution after unmount (no state update on an unmounted hook)", async () => {
    isAuthenticated.mockReturnValue(true);
    let resolveCapabilities: (value: unknown[]) => void = () => {};
    listCapabilities.mockImplementation(() => new Promise((resolve) => { resolveCapabilities = resolve; }));
    getCatalog.mockResolvedValue([]);
    getSummary.mockResolvedValue(null);
    getMeCompanies.mockResolvedValue([]);

    const { result, unmount } = renderHook(() => useModuleAccess());
    unmount();
    await act(async () => {
      resolveCapabilities([]);
      await Promise.resolve();
    });
    expect(result.current.access).toEqual(emptyModuleAccess);
    expect(result.current.ready).toBe(false);
  });
});
