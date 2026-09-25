// SPDX-License-Identifier: Apache-2.0

// Company-switch path-preserve semantics. A richer design would choose between "preserve-path"
// and "module-root" per feature via catalog metadata; Kiban's registry catalog (CatalogEntry)
// carries no such per-feature metadata, so v1 always preserves the path (the common strategy;
// module-root would be the opt-in exception).
// Pure function, no React/router dependency — fully unit-testable (company-switch-path.test.ts).
const companyScopePattern = /^\/app\/c\/([^/]+)(\/.*)?$/;

/** Given the current pathname and the company id being switched TO, returns the destination
 * pathname: on a company-scoped route (`/app/c/:companyId/...`), rewrites just the companyId
 * segment, preserving everything after it. On any other route (global module routes, `/app`
 * itself), there is nothing to rewrite — switching companies changes context only, not location. */
export function getCompanySwitchDestination(pathname: string, newCompanyId: string): string {
  const match = pathname.match(companyScopePattern);
  if (!match) return pathname;

  const remainder = match[2] ?? "";
  return `/app/c/${encodeURIComponent(newCompanyId)}${remainder}`;
}
