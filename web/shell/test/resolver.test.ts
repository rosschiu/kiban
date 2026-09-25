// SPDX-License-Identifier: Apache-2.0

// Table-driven resolver suite: the numbered table below plus the dedicated matching/validation
// `describe` blocks keep every case traceable to its
// resolver stage (catalog lookup -> scope match -> capability check -> path match -> membership
// check -> feature-key gate -> outcome).
import { describe, expect, it } from "vitest";
import {
  assertValidModuleCatalog,
  normalizeModulePath,
  resolveModuleRoute,
  type ModuleCatalog,
  type ModuleRouteRequest,
} from "../src/resolver/resolver";

const catalog: ModuleCatalog = [
  {
    moduleKey: "diagnostics",
    scope: "global",
    routes: [
      { id: "diagnostics.overview", path: "/overview", featureKey: "platform.diagnostics.view", remoteExport: "DiagnosticsOverviewPage" },
      { id: "diagnostics.event", path: "/events/:eventId", featureKey: "platform.diagnostics.view", remoteExport: "DiagnosticsEventPage" },
    ],
  },
  {
    moduleKey: "client-asset",
    scope: "company",
    routes: [
      { id: "client-asset.assets.list", path: "/assets", featureKey: "client-asset.assets.view", remoteExport: "AssetListPage" },
      { id: "client-asset.assets.detail", path: "/assets/:assetId", featureKey: "client-asset.assets.view", remoteExport: "AssetDetailPage" },
      { id: "client-asset.assets.new", path: "/assets/new", featureKey: "client-asset.assets.edit", remoteExport: "AssetCreatePage" },
      { id: "client-asset.assets.edit", path: "/assets/:assetId/edit", featureKey: "client-asset.assets.edit", remoteExport: "AssetEditPage" },
    ],
  },
];

const baseAccess = {
  availableModuleKeys: ["diagnostics", "client-asset"],
  globalFeatureKeys: ["platform.diagnostics.view"],
  moduleKeysByCompany: {
    "company-a": ["client-asset"],
    "company-b": ["client-asset"],
  },
  featureKeysByCompany: {
    "company-a": ["client-asset.assets.view"],
    "company-b": [],
  },
} satisfies Pick<
  ModuleRouteRequest,
  "availableModuleKeys" | "globalFeatureKeys" | "moduleKeysByCompany" | "featureKeysByCompany"
>;

describe("normalizeModulePath", () => {
  it("normalizes missing, empty, and slash-padded paths to a rooted path", () => {
    expect(normalizeModulePath(undefined)).toBe("/");
    expect(normalizeModulePath("")).toBe("/");
    expect(normalizeModulePath("assets/A-100/")).toBe("/assets/A-100");
    expect(normalizeModulePath("/assets/A-100")).toBe("/assets/A-100");
  });

  it("does not re-decode values already decoded by the router", () => {
    expect(normalizeModulePath("events/Quarterly Review")).toBe("/events/Quarterly Review");
    expect(normalizeModulePath("events/100% complete")).toBe("/events/100% complete");
  });
});

describe("assertValidModuleCatalog", () => {
  it("rejects a duplicate module key", () => {
    expect(() =>
      assertValidModuleCatalog([
        { moduleKey: "one", scope: "global", routes: [] },
        { moduleKey: "one", scope: "company", routes: [] },
      ]),
    ).toThrow(/duplicate module key/i);
  });

  it("rejects a duplicate route id within a module", () => {
    expect(() =>
      assertValidModuleCatalog([
        {
          moduleKey: "one", scope: "global", routes: [
            { id: "dup", path: "/a", featureKey: "one.view", remoteExport: "A" },
            { id: "dup", path: "/b", featureKey: "one.view", remoteExport: "B" },
          ],
        },
      ]),
    ).toThrow(/duplicate route id/i);
  });

  it("rejects structurally ambiguous paths (differing param names, same shape)", () => {
    expect(() =>
      assertValidModuleCatalog([
        {
          moduleKey: "one", scope: "global", routes: [
            { id: "one.a", path: "/records/:recordId", featureKey: "one.view", remoteExport: "A" },
            { id: "one.b", path: "/records/:id", featureKey: "one.view", remoteExport: "B" },
          ],
        },
      ]),
    ).toThrow(/ambiguous/i);
  });

  it("rejects a trailing-slash duplicate of an existing static path", () => {
    expect(() =>
      assertValidModuleCatalog([
        {
          moduleKey: "one", scope: "global", routes: [
            { id: "one.a", path: "/records", featureKey: "one.view", remoteExport: "A" },
            { id: "one.b", path: "/records/", featureKey: "one.view", remoteExport: "B" },
          ],
        },
      ]),
    ).toThrow(/ambiguous/i);
  });

  it("rejects a structural (non-identical) path collision between a param and a static sibling", () => {
    expect(() =>
      assertValidModuleCatalog([
        {
          moduleKey: "one", scope: "global", routes: [
            { id: "one.a", path: "/assets/:assetId", featureKey: "one.view", remoteExport: "A" },
            { id: "one.b", path: "/:section/new", featureKey: "one.edit", remoteExport: "B" },
          ],
        },
      ]),
    ).toThrow(/ambiguous/i);
  });

  it("rejects an empty path segment", () => {
    expect(() =>
      assertValidModuleCatalog([
        { moduleKey: "one", scope: "global", routes: [{ id: "one.a", path: "/assets//edit", featureKey: "one.view", remoteExport: "A" }] },
      ]),
    ).toThrow(/empty path segment/i);
  });

  it("rejects an invalid param name", () => {
    expect(() =>
      assertValidModuleCatalog([
        { moduleKey: "one", scope: "global", routes: [{ id: "one.a", path: "/assets/:1bad", featureKey: "one.view", remoteExport: "A" }] },
      ]),
    ).toThrow(/invalid param/i);
  });

  it("rejects a repeated param name within one route", () => {
    expect(() =>
      assertValidModuleCatalog([
        { moduleKey: "one", scope: "global", routes: [{ id: "one.a", path: "/assets/:id/edit/:id", featureKey: "one.view", remoteExport: "A" }] },
      ]),
    ).toThrow(/repeats param/i);
  });

  it("accepts a well-formed catalog without throwing", () => {
    expect(() => assertValidModuleCatalog(catalog)).not.toThrow();
  });
});

type ResolveCase = {
  name: string;
  request: Partial<ModuleRouteRequest> & Pick<ModuleRouteRequest, "hostScope" | "moduleKey">;
  expected: ReturnType<typeof resolveModuleRoute>["status"];
  assert?: (outcome: ReturnType<typeof resolveModuleRoute>) => void;
};

const resolveCases: ResolveCase[] = [
  {
    name: "unknown module key -> module-unavailable (catalog lookup miss)",
    request: { hostScope: "global", moduleKey: "does-not-exist", modulePath: "overview" },
    expected: "module-unavailable",
  },
  {
    name: "company-scoped module requested on the global host -> module-unavailable (scope match)",
    request: { hostScope: "global", moduleKey: "client-asset", modulePath: "assets" },
    expected: "module-unavailable",
  },
  {
    name: "global module requested on a company host -> module-unavailable (scope match, reverse)",
    request: { hostScope: "company", companyId: "company-a", moduleKey: "diagnostics", modulePath: "overview" },
    expected: "module-unavailable",
  },
  {
    name: "module exists and is right-scoped but not capability-available -> module-unavailable",
    request: {
      hostScope: "company",
      companyId: "company-a",
      moduleKey: "client-asset",
      modulePath: "assets",
      availableModuleKeys: ["diagnostics"],
    },
    expected: "module-unavailable",
  },
  {
    name: "path has no matching route in the module -> route-not-found",
    request: { hostScope: "company", companyId: "company-a", moduleKey: "client-asset", modulePath: "missing" },
    expected: "route-not-found",
  },
  {
    name: "path segment count mismatch -> route-not-found",
    request: { hostScope: "company", companyId: "company-a", moduleKey: "client-asset", modulePath: "assets/A-100/edit/extra" },
    expected: "route-not-found",
  },
  {
    name: "company host with no companyId set -> access-denied (membership check)",
    request: { hostScope: "company", moduleKey: "client-asset", modulePath: "assets" },
    expected: "access-denied",
  },
  {
    name: "companyId set but module unreachable in that company -> access-denied (membership check)",
    request: {
      hostScope: "company",
      companyId: "company-a",
      moduleKey: "client-asset",
      modulePath: "assets/A-100",
      moduleKeysByCompany: { "company-a": [] },
      featureKeysByCompany: { "company-a": ["client-asset.assets.view"] },
    },
    expected: "access-denied",
  },
  {
    name: "reachable in company-a, but the SAME module/route is denied for company-b (isolation)",
    request: { hostScope: "company", companyId: "company-b", moduleKey: "client-asset", modulePath: "assets/A-100" },
    expected: "access-denied",
  },
  {
    name: "reachable but missing the page's feature key in that company -> access-denied (feature gate)",
    request: { hostScope: "company", companyId: "company-a", moduleKey: "client-asset", modulePath: "assets/A-100/edit" },
    expected: "access-denied",
  },
  {
    name: "global route with no global feature grant -> access-denied (feature gate, global)",
    request: {
      hostScope: "global",
      moduleKey: "diagnostics",
      modulePath: "overview",
      globalFeatureKeys: [],
    },
    expected: "access-denied",
  },
  {
    name: "company feature grants are never consulted for a global route (no scope bleed)",
    request: {
      hostScope: "global",
      moduleKey: "diagnostics",
      modulePath: "overview",
      globalFeatureKeys: [],
      featureKeysByCompany: { "company-a": ["platform.diagnostics.view"] },
    },
    expected: "access-denied",
  },
  {
    name: "ready: global module, static route, global feature grant present",
    request: { hostScope: "global", moduleKey: "diagnostics", modulePath: "overview" },
    expected: "ready",
    assert: (outcome) => {
      expect(outcome).toMatchObject({ status: "ready", route: { remoteExport: "DiagnosticsOverviewPage" }, params: {} });
      if (outcome.status === "ready") expect(outcome.companyId).toBeUndefined();
    },
  },
  {
    name: "ready: global module, parameterized route captures its param",
    request: { hostScope: "global", moduleKey: "diagnostics", modulePath: "events/EVT-9" },
    expected: "ready",
    assert: (outcome) => {
      expect(outcome).toMatchObject({ status: "ready", params: { eventId: "EVT-9" }, route: { remoteExport: "DiagnosticsEventPage" } });
    },
  },
  {
    name: "ready: company module, membership + feature grant both present, param captured, companyId echoed",
    request: { hostScope: "company", companyId: "company-a", moduleKey: "client-asset", modulePath: "assets/A-100" },
    expected: "ready",
    assert: (outcome) => {
      expect(outcome).toMatchObject({
        status: "ready",
        companyId: "company-a",
        params: { assetId: "A-100" },
        route: { remoteExport: "AssetDetailPage" },
      });
    },
  },
  {
    name: "ready: static /assets/new route wins over the parameterized /assets/:assetId sibling",
    request: {
      hostScope: "company",
      companyId: "company-a",
      moduleKey: "client-asset",
      modulePath: "assets/new",
      featureKeysByCompany: { "company-a": ["client-asset.assets.edit"] },
    },
    expected: "ready",
    assert: (outcome) => {
      expect(outcome).toMatchObject({ status: "ready", route: { id: "client-asset.assets.new" }, params: {} });
    },
  },
];

describe("resolveModuleRoute — table-driven (>= 15 cases)", () => {
  it.each(resolveCases)("$name", ({ request, expected, assert }) => {
    const outcome = resolveModuleRoute(catalog, { ...baseAccess, ...request });
    expect(outcome.status).toBe(expected);
    assert?.(outcome);
  });
});
