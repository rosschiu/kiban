// SPDX-License-Identifier: Apache-2.0

// Company switcher. v1 skeleton: a plain native <select> (no avatar colors, dirty-form confirm or
// optimistic-override rollback yet); a dependency-light select
// is enough to prove the real wiring (org.meCompanies -> options, activeCompanyId -> selection,
// onSwitch -> sdk session-context + path-preserve navigation) without adding a new shadcn
// primitive.
import type { OrgMeCompany } from "@rosschiu/kiban-sdk";

export interface CompanySwitcherProps {
  companies: readonly OrgMeCompany[];
  activeCompanyId: string | null;
  onSwitch: (companyId: string) => void;
}

/** Renders nothing when the caller belongs to no companies — there is nothing to switch between,
 * and an empty/disabled selector would just be noise (same "empty state is the final render, not
 * a loading stub" posture as SidebarNav). */
export function CompanySwitcher({ companies, activeCompanyId, onSwitch }: CompanySwitcherProps) {
  if (companies.length === 0) return null;

  return (
    <div data-testid="company-switcher" className="border-b border-sidebar-border px-4 py-2">
      <label htmlFor="company-switcher-select" className="mb-1 block text-xs font-medium text-muted-foreground">
        Company
      </label>
      <select
        id="company-switcher-select"
        data-testid="company-switcher-select"
        className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm text-foreground"
        value={activeCompanyId ?? ""}
        onChange={(event) => onSwitch(event.target.value)}
      >
        <option value="" disabled>
          Select a company
        </option>
        {companies.map((company) => (
          <option key={company.id} value={company.id}>
            {company.name}
          </option>
        ))}
      </select>
    </div>
  );
}
