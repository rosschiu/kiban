// SPDX-License-Identifier: Apache-2.0

// Pure nav composition logic (catalog ⋈ capabilities
// ⋈ effective-access summary → sidebar entries, navOrder sorted, empty ⇒ empty). No React, no
// I/O — a pure function of already-fetched SDK data => resolver input / sidebar entries, exactly
// mirroring resolver.ts's own "pure function, table-driven test" shape so this is fully covered
// without any network/DOM involved (compose.test.ts).
import type { Capability, CatalogEntry, EffectiveAccessSummary, OrgMeCompany } from "@rosschiu/kiban-sdk";
import type { RegisteredModule } from "../modules/registry";
import type { NavEntry } from "./sidebar-nav";

// The feature key `internal/gateway/platform_admin.go`'s guard checks
// (auth.platform_administration.access) — the SAME key `useModuleAccess`'s globalFeatureKeys
// already carries (internal/authz/summary.go's global-scope summaryFeatureKeys), so gating the
// synthetic "Positions" nav entry on it needs no new fetch, just a membership check on data
// already composed.
const superadminFeatureKey = "auth.platform_administration.access";

/** Resolver access inputs (resolver/resolver.ts's ModuleRouteRequest fields), sourced from the
 * catalog/capability/access-summary composition below. Stable shape —
 * every route-host call site keeps reading exactly this. */
export interface ModuleAccess {
  availableModuleKeys: readonly string[];
  globalFeatureKeys: readonly string[];
  moduleKeysByCompany: Readonly<Record<string, readonly string[]>>;
  featureKeysByCompany: Readonly<Record<string, readonly string[]>>;
}

export const emptyModuleAccess: ModuleAccess = {
  availableModuleKeys: [],
  globalFeatureKeys: [],
  moduleKeysByCompany: {},
  featureKeysByCompany: {},
};

/** Raw material for both `computeModuleAccess` and `computeNavEntries` — everything the SDK-
 * backed hooks fetch, before any shell-specific interpretation. */
export interface PlatformComposition {
  capabilities: readonly Capability[];
  catalog: readonly CatalogEntry[];
  /** The caller's global-scope EffectiveAccessSummary (`summary()`, no companyId) — null when
   * the fetch failed or the caller isn't authenticated. */
  globalSummary: EffectiveAccessSummary | null;
  /** Companies the caller has an active membership in (`org.meCompanies()` — the company-switcher
   * source). */
  meCompanies: readonly OrgMeCompany[];
  /** User-facing reason when a leaf fetch failed because a service was unavailable (5xx or no
   * connection); null/absent when every leaf answered (even with a 403/404). */
  unavailable?: string | null;
  /** One EffectiveAccessSummary per company in `meCompanies` (`summary(companyId)`), keyed by
   * company id. A missing/null entry means that company's fetch failed — treated as "no company-
   * scoped feature keys granted" (fail closed), never an error into the route tree. */
  companySummaries: ReadonlyMap<string, EffectiveAccessSummary | null>;
}

function isCapabilityEnabled(capability: Capability): boolean {
  return capability.installed && capability.enabled && capability.missingDependencies.length === 0;
}

/** catalog ⋈ capabilities ⋈ effective-access summary -> resolver.ts's ModuleRouteRequest access
 * fields. `availableModuleKeys` is scope-agnostic (installed +
 * enabled + active, matching resolver.ts's own doc comment for that field) — company-scoped
 * reachability is layered on top via `moduleKeysByCompany`, restricted to modules the catalog
 * marks `scopeType: "company"` and companies the caller is an active member of (org.meCompanies
 * is itself already membership-filtered — "shell reachability is explicit"). */
export function computeModuleAccess(data: PlatformComposition): ModuleAccess {
  const enabledModuleKeys = new Set(data.capabilities.filter(isCapabilityEnabled).map((c) => c.module));
  const catalogByKey = new Map(data.catalog.map((entry) => [entry.moduleKey, entry] as const));

  const availableModuleKeys = [...enabledModuleKeys].filter((key) => catalogByKey.get(key)?.isActive === true);
  const companyScopedAvailableModuleKeys = availableModuleKeys.filter(
    (key) => catalogByKey.get(key)?.scopeType === "company",
  );

  const globalFeatureKeys = data.globalSummary?.featureKeys ?? [];

  const moduleKeysByCompany: Record<string, readonly string[]> = {};
  const featureKeysByCompany: Record<string, readonly string[]> = {};
  for (const company of data.meCompanies) {
    moduleKeysByCompany[company.id] = companyScopedAvailableModuleKeys;
    featureKeysByCompany[company.id] = data.companySummaries.get(company.id)?.featureKeys ?? [];
  }

  return { availableModuleKeys, globalFeatureKeys, moduleKeysByCompany, featureKeysByCompany };
}

/** access ⋈ the local module registry (modules/registry.ts's own nav descriptors: label/icon/
 * navOrder) -> sidebar entries, sorted by navOrder then moduleKey. Only modules the shell
 * actually implements (present in `registry`) can ever
 * appear — no module list is hardcoded, because an empty
 * registry (today) or an access composition with no available modules both fall straight through
 * to an empty list, never a fallback. A company-scoped module with no `activeCompanyId` selected
 * yet is omitted (there is nowhere to link it) rather than shown disabled — v1 keeps the sidebar
 * itself state-free about "why not". Registry catalog `displayName` wins over the local nav
 * descriptor's label when present (server is the naming source of truth); the local label is the
 * fallback for a module the registry catalog doesn't (yet) know about. */
export function computeNavEntries(
  access: ModuleAccess,
  catalog: readonly CatalogEntry[],
  registry: Readonly<Record<string, RegisteredModule>>,
  activeCompanyId: string | null,
): NavEntry[] {
  const catalogByKey = new Map(catalog.map((entry) => [entry.moduleKey, entry] as const));
  const ranked: (NavEntry & { navOrder: number })[] = [];

  for (const [moduleKey, registered] of Object.entries(registry)) {
    if (!access.availableModuleKeys.includes(moduleKey)) continue;

    const scope = registered.catalog.scope;
    let href: string;
    if (scope === "company") {
      if (!activeCompanyId) continue;
      if (!(access.moduleKeysByCompany[activeCompanyId] ?? []).includes(moduleKey)) continue;
      href = `/app/c/${encodeURIComponent(activeCompanyId)}/${moduleKey}`;
    } else {
      href = `/app/${moduleKey}`;
    }

    ranked.push({
      moduleKey,
      label: catalogByKey.get(moduleKey)?.displayName ?? registered.nav.label,
      href,
      icon: registered.nav.icon,
      navOrder: registered.nav.navOrder,
    });
  }

  const entries = ranked
    .sort((left, right) => left.navOrder - right.navOrder || left.moduleKey.localeCompare(right.moduleKey))
    .map(({ navOrder: _navOrder, ...entry }) => entry);

  // The sample shell's minimal position-based-access admin surface — a superadmin-
  // only nav entry, hidden entirely (never rendered disabled/greyed) for every other caller,
  // same "hidden, not disabled" posture as a company-scoped module entry with no active company
  // (above). Appended last (not catalog/registry driven, so it has no navOrder to rank by) —
  // NOT a module route (no manifest, no scope), so it is deliberately excluded from `ranked`'s
  // catalog/registry loop entirely.
  if (access.globalFeatureKeys.includes(superadminFeatureKey)) {
    entries.push({ moduleKey: "admin-positions", label: "Positions", href: "/app/admin/positions" });
    // The Groups admin page — same superadmin-only, hidden-not-disabled posture as
    // Positions above, appended right after it.
    entries.push({ moduleKey: "admin-groups", label: "Groups", href: "/app/admin/groups" });
  }

  return entries;
}
