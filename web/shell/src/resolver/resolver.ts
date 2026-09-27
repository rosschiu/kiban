// SPDX-License-Identifier: Apache-2.0

// Pure runtime-module route resolver. Nav/labels/icons/ordering/scope tree are all
// runtime-derived; this file is the resolver half of that property, over Kiban's local module
// registry. The matching/precedence/gating rules below are a compatibility contract: change them
// only deliberately, with the table-driven tests updated to match.
//
// No React, no I/O — a pure function of (catalog, request) => outcome, so it is fully covered by
// a table-driven unit suite with no DOM/router involved (resolver.test.ts).

export type ModuleScope = "global" | "company";

export interface ModuleRouteDefinition {
  /** Stable id, unique within the module (catalog validation rejects duplicates). */
  id: string;
  /** `/`-rooted path pattern; segments starting with `:` are params, e.g. `/assets/:assetId`. */
  path: string;
  /** Feature key gating this specific page (checked against the caller's granted feature keys,
   * scoped to hostScope). */
  featureKey: string;
  /** Name of the exported component the local registry resolves this route to. */
  remoteExport: string;
}

export interface ModuleDefinition {
  moduleKey: string;
  scope: ModuleScope;
  routes: readonly ModuleRouteDefinition[];
}

export type ModuleCatalog = readonly ModuleDefinition[];

export interface ModulePageContext {
  moduleKey: string;
  companyId?: string;
  featureKey: string;
  params: Record<string, string>;
  remoteExport: string;
}

export type ModuleRouteOutcome =
  | { status: "module-unavailable"; moduleKey: string }
  | { status: "route-not-found"; moduleKey: string; modulePath: string }
  | { status: "access-denied"; moduleKey: string; featureKey: string }
  | {
      status: "ready";
      module: ModuleDefinition;
      route: ModuleRouteDefinition;
      params: Record<string, string>;
      companyId?: string;
    };

export interface ModuleRouteRequest {
  /** Which route host is asking — the global host (`/app/$module/$`) or the company-scoped host
   * (`/app/c/$companyId/$module/$`). */
  hostScope: ModuleScope;
  companyId?: string;
  moduleKey: string;
  /** The catch-all remainder after `/app/$module/` (or the company-scoped equivalent), already
   * URI-decoded by the router. */
  modulePath?: string;
  /** Module keys the caller's capability/catalog composition currently makes available at all
   * (installed + enabled). Scope + capability check. */
  availableModuleKeys: readonly string[];
  /** Feature keys granted to the caller at global scope. */
  globalFeatureKeys: readonly string[];
  /** Company id -> module keys the caller can reach in that company. Membership check for
   * company-scoped hosts. */
  moduleKeysByCompany: Readonly<Record<string, readonly string[]>>;
  /** Company id -> feature keys granted to the caller in that company. */
  featureKeysByCompany: Readonly<Record<string, readonly string[]>>;
}

interface ModuleRouteMatch {
  route: ModuleRouteDefinition;
  params: Record<string, string>;
}

/** Normalizes a catch-all remainder to a `/`-rooted path with no trailing slash: `undefined`/`""`
 * -> `"/"`; strips leading/trailing slashes otherwise. Values are assumed already decoded by the
 * router (TanStack Router decodes catch-all segments) — this never itself decodes. */
export function normalizeModulePath(modulePath?: string): string {
  const trimmed = (modulePath ?? "").replace(/^\/+|\/+$/g, "");
  return trimmed ? `/${trimmed}` : "/";
}

function splitPath(path: string): string[] {
  const normalized = normalizeModulePath(path);
  return normalized === "/" ? [] : normalized.slice(1).split("/");
}

/** The path with every param segment collapsed to `:` — used to detect two routes that would
 * always match the same set of concrete paths (duplicate/ambiguous manifest entries). */
function structuralRoutePath(path: string): string {
  return splitPath(path)
    .map((segment) => (segment.startsWith(":") ? ":" : segment))
    .join("/");
}

function routeSpecificity(route: ModuleRouteDefinition): [staticSegmentCount: number, totalSegmentCount: number] {
  const segments = splitPath(route.path);
  return [segments.filter((segment) => !segment.startsWith(":")).length, segments.length];
}

/** True when two same-length routes could both match at least one concrete path (any segment
 * pair is either identical, or at least one side is a param). Distinct from
 * `structuralRoutePath` equality: this also catches e.g. `/assets/:assetId` vs `/:section/new`
 * colliding at `/assets/new`, which have different structural paths but overlapping segments. */
function routesOverlap(left: ModuleRouteDefinition, right: ModuleRouteDefinition): boolean {
  const leftSegments = splitPath(left.path);
  const rightSegments = splitPath(right.path);
  if (leftSegments.length !== rightSegments.length) {
    return false;
  }

  const [leftStatic] = routeSpecificity(left);
  const [rightStatic] = routeSpecificity(right);
  if (leftStatic !== rightStatic) {
    return false;
  }

  return leftSegments.every((leftSegment, index) => {
    const rightSegment = rightSegments[index]!;
    return leftSegment === rightSegment || leftSegment.startsWith(":") || rightSegment.startsWith(":");
  });
}

function validateRouteDefinition(moduleKey: string, route: ModuleRouteDefinition): void {
  const segments = splitPath(route.path);
  const paramNames = new Set<string>();

  for (const segment of segments) {
    if (!segment) {
      throw new Error(`Module ${moduleKey} route ${route.id} contains an empty path segment: ${route.path}`);
    }
    if (!segment.startsWith(":")) {
      continue;
    }
    const paramName = segment.slice(1);
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(paramName)) {
      throw new Error(`Module ${moduleKey} route ${route.id} has an invalid param name: ${segment}`);
    }
    if (paramNames.has(paramName)) {
      throw new Error(`Module ${moduleKey} route ${route.id} repeats param :${paramName}`);
    }
    paramNames.add(paramName);
  }
}

/** Validates a full catalog: unique module keys, unique route ids within a module, and no
 * structurally ambiguous or overlapping route paths within a module. Throws on the first
 * violation found (fail fast — a bad catalog should never reach the resolver). Call this once,
 * e.g. at catalog-load time in modules/registry.ts; the resolver itself does not call it (kept
 * pure and cheap for per-navigation calls). */
export function assertValidModuleCatalog(catalog: ModuleCatalog): void {
  const moduleKeys = new Set<string>();

  for (const module of catalog) {
    if (moduleKeys.has(module.moduleKey)) {
      throw new Error(`Duplicate module key in catalog: ${module.moduleKey}`);
    }
    moduleKeys.add(module.moduleKey);

    const routeIds = new Set<string>();
    const structuralPaths = new Set<string>();
    const validatedRoutes: ModuleRouteDefinition[] = [];
    for (const route of module.routes) {
      validateRouteDefinition(module.moduleKey, route);
      if (routeIds.has(route.id)) {
        throw new Error(`Duplicate route id in module ${module.moduleKey}: ${route.id}`);
      }
      routeIds.add(route.id);

      const structuralPath = structuralRoutePath(route.path);
      if (structuralPaths.has(structuralPath)) {
        throw new Error(`Ambiguous route path in module ${module.moduleKey}: ${route.path}`);
      }
      structuralPaths.add(structuralPath);

      if (validatedRoutes.some((candidate) => routesOverlap(candidate, route))) {
        throw new Error(`Ambiguous overlapping route path in module ${module.moduleKey}: ${route.path}`);
      }
      validatedRoutes.push(route);
    }
  }
}

/** Matches a concrete module-relative path against a module's route list. Candidates are sorted
 * by specificity — more static segments first, then more total segments — so a static route
 * (`/assets/new`) always wins over a param sibling (`/assets/:assetId`) of the same length. Exact
 * segment count is required (no partial/prefix matches). */
function matchModuleRoute(
  routes: readonly ModuleRouteDefinition[],
  modulePath?: string,
): ModuleRouteMatch | null {
  const actualSegments = splitPath(modulePath ?? "");
  const candidates = [...routes].sort((left, right) => {
    const [leftStatic, leftLength] = routeSpecificity(left);
    const [rightStatic, rightLength] = routeSpecificity(right);
    return rightStatic - leftStatic || rightLength - leftLength;
  });

  for (const route of candidates) {
    const routeSegments = splitPath(route.path);
    if (routeSegments.length !== actualSegments.length) {
      continue;
    }

    const params: Record<string, string> = {};
    let matches = true;
    for (let index = 0; index < routeSegments.length; index += 1) {
      const expected = routeSegments[index]!;
      const actual = actualSegments[index]!;
      if (expected.startsWith(":")) {
        if (!actual) {
          matches = false;
          break;
        }
        params[expected.slice(1)] = actual;
      } else if (expected !== actual) {
        matches = false;
        break;
      }
    }

    if (matches) {
      return { route, params };
    }
  }

  return null;
}

/** The resolver proper: catalog lookup -> scope match -> capability check -> path match ->
 * membership check -> feature-key gate -> outcome. Each stage short-circuits to a distinct
 * failure status; only a request that clears every stage resolves to "ready". */
export function resolveModuleRoute(catalog: ModuleCatalog, request: ModuleRouteRequest): ModuleRouteOutcome {
  // Stage 1+2: catalog lookup + scope match. A module that doesn't exist, is scoped for the
  // other host, or isn't in the caller's available-modules set is indistinguishable from the
  // caller's point of view — all three read as "not here".
  const module = catalog.find((candidate) => candidate.moduleKey === request.moduleKey);
  if (!module || module.scope !== request.hostScope || !request.availableModuleKeys.includes(module.moduleKey)) {
    return { status: "module-unavailable", moduleKey: request.moduleKey };
  }

  // Stage 3: path match within the module's own route list.
  const modulePath = normalizeModulePath(request.modulePath);
  const match = matchModuleRoute(module.routes, modulePath);
  if (!match) {
    return { status: "route-not-found", moduleKey: module.moduleKey, modulePath };
  }

  // Stage 4: membership check — company hosts require the caller to reach this module in the
  // named company specifically (module-level reachability, separate from the page's own feature
  // gate below).
  if (
    request.hostScope === "company"
    && (!request.companyId || !(request.moduleKeysByCompany[request.companyId] ?? []).includes(module.moduleKey))
  ) {
    return { status: "access-denied", moduleKey: module.moduleKey, featureKey: match.route.featureKey };
  }

  // Stage 5: feature-key gate, scoped by host — global routes check global grants only; company
  // routes check that company's grants only (never cross-company, never global-for-company).
  const grantedFeatureKeys = request.hostScope === "global"
    ? request.globalFeatureKeys
    : request.companyId
      ? request.featureKeysByCompany[request.companyId] ?? []
      : [];
  if (!grantedFeatureKeys.includes(match.route.featureKey)) {
    return { status: "access-denied", moduleKey: module.moduleKey, featureKey: match.route.featureKey };
  }

  return {
    status: "ready",
    module,
    route: match.route,
    params: match.params,
    ...(request.companyId ? { companyId: request.companyId } : {}),
  };
}
