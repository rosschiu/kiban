// SPDX-License-Identifier: Apache-2.0

import type { Capability, CatalogEntry, EffectiveAccessSummary, OrgMeCompany } from "@rosschiu/kiban-sdk";
import { describe, expect, it } from "vitest";
import type { RegisteredModule } from "../../src/modules/registry";
import { computeModuleAccess, computeNavEntries, emptyModuleAccess, type PlatformComposition } from "../../src/nav/compose";

function capability(overrides: Partial<Capability> = {}): Capability {
  return { module: "diagnostics", installed: true, enabled: true, dependencies: [], missingDependencies: [], ...overrides };
}

function catalogEntry(overrides: Partial<CatalogEntry> = {}): CatalogEntry {
  return {
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
    ...overrides,
  };
}

function summary(overrides: Partial<EffectiveAccessSummary> = {}): EffectiveAccessSummary {
  return {
    apiVersion: 1,
    subjectId: "user-1",
    companyId: "",
    moduleKey: "",
    featureKeys: [],
    roleBindings: [],
    objectAccess: [],
    rowScopes: [],
    fieldPolicies: [],
    ...overrides,
  };
}

function company(overrides: Partial<OrgMeCompany> = {}): OrgMeCompany {
  return { id: "company-a", code: "A", name: "Company A", isActive: true, ...overrides };
}

function composition(overrides: Partial<PlatformComposition> = {}): PlatformComposition {
  return {
    capabilities: [],
    catalog: [],
    globalSummary: null,
    meCompanies: [],
    companySummaries: new Map(),
    ...overrides,
  };
}

describe("computeModuleAccess", () => {
  it("returns the empty shape for an empty composition (empty catalog ⇒ empty access)", () => {
    expect(computeModuleAccess(composition())).toEqual(emptyModuleAccess);
  });

  it("excludes a capability that is not installed/enabled or has missing dependencies", () => {
    const access = computeModuleAccess(
      composition({
        capabilities: [
          capability({ module: "broken", missingDependencies: ["core"] }),
          capability({ module: "off", enabled: false }),
          capability({ module: "absent", installed: false }),
        ],
        catalog: [catalogEntry({ moduleKey: "broken" }), catalogEntry({ moduleKey: "off" }), catalogEntry({ moduleKey: "absent" })],
      }),
    );
    expect(access.availableModuleKeys).toEqual([]);
  });

  it("excludes an enabled capability whose catalog entry is inactive", () => {
    const access = computeModuleAccess(
      composition({
        capabilities: [capability({ module: "diagnostics" })],
        catalog: [catalogEntry({ moduleKey: "diagnostics", isActive: false })],
      }),
    );
    expect(access.availableModuleKeys).toEqual([]);
  });

  it("excludes a capability with no matching catalog entry at all", () => {
    const access = computeModuleAccess(
      composition({ capabilities: [capability({ module: "unknown-to-catalog" })], catalog: [] }),
    );
    expect(access.availableModuleKeys).toEqual([]);
  });

  it("includes an installed+enabled+active module in availableModuleKeys regardless of scope", () => {
    const access = computeModuleAccess(
      composition({
        capabilities: [capability({ module: "diagnostics" }), capability({ module: "client-asset" })],
        catalog: [
          catalogEntry({ moduleKey: "diagnostics", scopeType: "global" }),
          catalogEntry({ moduleKey: "client-asset", scopeType: "company" }),
        ],
      }),
    );
    expect([...access.availableModuleKeys].sort()).toEqual(["client-asset", "diagnostics"]);
  });

  it("takes globalFeatureKeys from the global-scope summary only", () => {
    const access = computeModuleAccess(composition({ globalSummary: summary({ featureKeys: ["diagnostics.viewer.access"] }) }));
    expect(access.globalFeatureKeys).toEqual(["diagnostics.viewer.access"]);
  });

  it("maps company-scoped available modules into moduleKeysByCompany for every meCompanies entry, excluding global-scope modules", () => {
    const access = computeModuleAccess(
      composition({
        capabilities: [capability({ module: "diagnostics" }), capability({ module: "client-asset" })],
        catalog: [
          catalogEntry({ moduleKey: "diagnostics", scopeType: "global" }),
          catalogEntry({ moduleKey: "client-asset", scopeType: "company" }),
        ],
        meCompanies: [company({ id: "company-a" }), company({ id: "company-b" })],
      }),
    );
    expect(access.moduleKeysByCompany).toEqual({
      "company-a": ["client-asset"],
      "company-b": ["client-asset"],
    });
  });

  it("maps each company's own summary featureKeys into featureKeysByCompany, defaulting to empty on a missing/null summary", () => {
    const access = computeModuleAccess(
      composition({
        meCompanies: [company({ id: "company-a" }), company({ id: "company-b" })],
        companySummaries: new Map([
          ["company-a", summary({ featureKeys: ["client-asset.viewer.access"] })],
          ["company-b", null],
        ]),
      }),
    );
    expect(access.featureKeysByCompany).toEqual({
      "company-a": ["client-asset.viewer.access"],
      "company-b": [],
    });
  });

  it("never leaks one company's feature keys into another's", () => {
    const access = computeModuleAccess(
      composition({
        meCompanies: [company({ id: "company-a" }), company({ id: "company-b" })],
        companySummaries: new Map([
          ["company-a", summary({ featureKeys: ["a.only"] })],
          ["company-b", summary({ featureKeys: ["b.only"] })],
        ]),
      }),
    );
    expect(access.featureKeysByCompany["company-a"]).toEqual(["a.only"]);
    expect(access.featureKeysByCompany["company-b"]).toEqual(["b.only"]);
  });
});

function registeredModule(moduleKey: string, overrides: Partial<RegisteredModule> = {}): RegisteredModule {
  return {
    catalog: { moduleKey, scope: "global", routes: [] },
    nav: { label: moduleKey, navOrder: 100 },
    pages: {},
    ...overrides,
  };
}

describe("computeNavEntries", () => {
  it("returns an empty list for an empty registry (empty catalog ⇒ empty nav)", () => {
    expect(computeNavEntries(emptyModuleAccess, [], {}, null)).toEqual([]);
  });

  it("omits a registered module that is not in availableModuleKeys", () => {
    const entries = computeNavEntries(
      emptyModuleAccess,
      [],
      { diagnostics: registeredModule("diagnostics") },
      null,
    );
    expect(entries).toEqual([]);
  });

  it("includes an available global-scope module, using the catalog displayName over the local label", () => {
    const access = { ...emptyModuleAccess, availableModuleKeys: ["diagnostics"] };
    const entries = computeNavEntries(
      access,
      [catalogEntry({ moduleKey: "diagnostics", displayName: "Diagnostics Suite" })],
      { diagnostics: registeredModule("diagnostics", { nav: { label: "fallback label", navOrder: 10 } }) },
      null,
    );
    expect(entries).toEqual([{ moduleKey: "diagnostics", label: "Diagnostics Suite", href: "/app/diagnostics", icon: undefined }]);
  });

  it("falls back to the local nav label when the catalog does not know the module", () => {
    const access = { ...emptyModuleAccess, availableModuleKeys: ["diagnostics"] };
    const entries = computeNavEntries(
      access,
      [],
      { diagnostics: registeredModule("diagnostics", { nav: { label: "Local Label", navOrder: 10 } }) },
      null,
    );
    expect(entries[0]?.label).toBe("Local Label");
  });

  it("omits a company-scoped module when no company is active", () => {
    const access = {
      ...emptyModuleAccess,
      availableModuleKeys: ["client-asset"],
      moduleKeysByCompany: { "company-a": ["client-asset"] },
    };
    const entries = computeNavEntries(
      access,
      [],
      { "client-asset": registeredModule("client-asset", { catalog: { moduleKey: "client-asset", scope: "company", routes: [] } }) },
      null,
    );
    expect(entries).toEqual([]);
  });

  it("includes a company-scoped module with a /app/c/:companyId href when reachable in the active company", () => {
    const access = {
      ...emptyModuleAccess,
      availableModuleKeys: ["client-asset"],
      moduleKeysByCompany: { "company-a": ["client-asset"] },
    };
    const entries = computeNavEntries(
      access,
      [],
      { "client-asset": registeredModule("client-asset", { catalog: { moduleKey: "client-asset", scope: "company", routes: [] } }) },
      "company-a",
    );
    expect(entries).toEqual([{ moduleKey: "client-asset", label: "client-asset", href: "/app/c/company-a/client-asset", icon: undefined }]);
  });

  it("omits a company-scoped module the active company cannot reach, even if available elsewhere", () => {
    const access = {
      ...emptyModuleAccess,
      availableModuleKeys: ["client-asset"],
      moduleKeysByCompany: { "company-b": ["client-asset"] },
    };
    const entries = computeNavEntries(
      access,
      [],
      { "client-asset": registeredModule("client-asset", { catalog: { moduleKey: "client-asset", scope: "company", routes: [] } }) },
      "company-a",
    );
    expect(entries).toEqual([]);
  });

  it("sorts by navOrder ascending, then moduleKey for ties", () => {
    const access = { ...emptyModuleAccess, availableModuleKeys: ["b-module", "a-module", "c-module"] };
    const entries = computeNavEntries(
      access,
      [],
      {
        "b-module": registeredModule("b-module", { nav: { label: "B", navOrder: 20 } }),
        "a-module": registeredModule("a-module", { nav: { label: "A", navOrder: 20 } }),
        "c-module": registeredModule("c-module", { nav: { label: "C", navOrder: 10 } }),
      },
      null,
    );
    expect(entries.map((entry) => entry.moduleKey)).toEqual(["c-module", "a-module", "b-module"]);
  });

  it("carries the local nav descriptor's icon through", () => {
    const icon = (() => null) as never;
    const access = { ...emptyModuleAccess, availableModuleKeys: ["diagnostics"] };
    const entries = computeNavEntries(
      access,
      [],
      { diagnostics: registeredModule("diagnostics", { nav: { label: "Diagnostics", navOrder: 10, icon } }) },
      null,
    );
    expect(entries[0]?.icon).toBe(icon);
  });

  // ---- The superadmin-only "Positions" entry. ----

  it("omits the Positions entry when the caller lacks auth.platform_administration.access", () => {
    const access = { ...emptyModuleAccess, globalFeatureKeys: [] };
    expect(computeNavEntries(access, [], {}, null)).toEqual([]);
  });

  it("appends a Positions entry (not catalog/registry driven) when the caller holds auth.platform_administration.access", () => {
    const access = { ...emptyModuleAccess, globalFeatureKeys: ["auth.platform_administration.access"] };
    const entries = computeNavEntries(access, [], {}, null);
    expect(entries).toEqual([
      { moduleKey: "admin-positions", label: "Positions", href: "/app/admin/positions" },
      { moduleKey: "admin-groups", label: "Groups", href: "/app/admin/groups" },
    ]);
  });

  it("appends the Positions entry AFTER catalog-driven entries, regardless of the caller's active company", () => {
    const access = {
      ...emptyModuleAccess,
      availableModuleKeys: ["diagnostics"],
      globalFeatureKeys: ["auth.platform_administration.access"],
    };
    const entries = computeNavEntries(
      access,
      [],
      { diagnostics: registeredModule("diagnostics", { nav: { label: "Diagnostics", navOrder: 10 } }) },
      "company-a",
    );
    expect(entries.map((entry) => entry.moduleKey)).toEqual(["diagnostics", "admin-positions", "admin-groups"]);
  });

  // ---- The superadmin-only "Groups" entry, next to Positions. ----

  it("omits the Groups entry when the caller lacks auth.platform_administration.access", () => {
    const access = { ...emptyModuleAccess, globalFeatureKeys: [] };
    expect(computeNavEntries(access, [], {}, null)).toEqual([]);
  });

  it("appends the Groups entry right after Positions when the caller holds auth.platform_administration.access", () => {
    const access = { ...emptyModuleAccess, globalFeatureKeys: ["auth.platform_administration.access"] };
    const entries = computeNavEntries(access, [], {}, null);
    expect(entries[1]).toEqual({ moduleKey: "admin-groups", label: "Groups", href: "/app/admin/groups" });
  });
});
