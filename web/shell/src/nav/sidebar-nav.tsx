// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import type { LucideIcon } from "lucide-react";
import { CloudOff, LayoutGrid, UserX } from "lucide-react";
import { EmptyState } from "../ui/empty-state";
import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem } from "../ui/sidebar";

export interface NavEntry {
  moduleKey: string;
  label: string;
  href: string;
  icon?: LucideIcon;
  /** Unread/activity count. Omitted or 0 renders no pill. */
  badge?: number;
}

export interface SidebarNavProps {
  /** Catalog-derived nav entries. Composition (catalog ⋈ capabilities ⋈ access summary,
   * navOrder sorting) lives in compose.ts — this component just renders
   * whatever it is given, with no hidden fallback data anywhere in between (no hardcoded module
   * lists). */
  entries: readonly NavEntry[];
  /** false while the session composition is still loading — renders a quiet skeleton instead of
   * the "No modules installed" empty state (loading ≠ empty). Defaults true so
   * existing call sites/tests keep the original semantics. */
  ready?: boolean;
  /** false when the caller belongs to no company (org.meCompanies is empty) — with no entries,
   * renders the "No company membership yet" empty state instead of "No modules installed": a
   * freshly provisioned user's honest first screen. Defaults true so existing call
   * sites/tests keep the original semantics. */
  hasCompanies?: boolean;
  /** Set when the composition could not be loaded because a service was down (5xx/no
   * connection) — with no entries, renders a "could not load" state carrying this message
   * instead of "No modules installed" (an outage is not an empty catalog). */
  unavailable?: string;
  /** Current pathname, for the active-item highlight (using sidebar-07's own `isActive`
   * affordance). Omitted entries
   * never render as active. */
  activePathname?: string;
}

/** Capability-driven sidebar nav, rendered through shadcn's sidebar-07 primitives (one
 * "Platform" SidebarGroup, a SidebarMenuButton per module). Kiban's compose.ts emits one FLAT
 * entry per module — no per-module sub-features — so this renders each
 * entry as a direct link, not a Collapsible-with-sub-items accordion: Kiban's nav model has
 * nothing to nest yet, and both e2e suites locate a module by `getByRole("link", ...)` directly on
 * its own row — a Collapsible trigger is a *button*, not a link, which would break that contract.
 * An empty `entries` list renders NO nav items and
 * no placeholder copy — the empty state IS the correct, final render for an empty catalog, not a
 * loading/error condition. */
export function SidebarNav({ entries, ready = true, hasCompanies = true, unavailable, activePathname }: SidebarNavProps) {
  if (!ready && entries.length === 0) {
    return (
      <div data-testid="sidebar-nav-loading" aria-busy="true" className="flex flex-col gap-2 px-4 py-2 group-data-[collapsible=icon]:hidden">
        <div className="h-4 w-28 animate-pulse rounded-md bg-sidebar-accent" />
        <div className="h-4 w-24 animate-pulse rounded-md bg-sidebar-accent" />
      </div>
    );
  }
  if (entries.length === 0 && unavailable) {
    return (
      <div data-testid="sidebar-nav-unavailable" className="overflow-hidden px-2 group-data-[collapsible=icon]:hidden">
        <EmptyState icon={CloudOff} title="Modules could not be loaded" description={unavailable} />
      </div>
    );
  }
  if (entries.length === 0 && !hasCompanies) {
    return (
      <div data-testid="sidebar-nav-no-membership" className="overflow-hidden px-2 group-data-[collapsible=icon]:hidden">
        <EmptyState
          icon={UserX}
          title="No company membership yet"
          description="Your account is not a member of any company yet. Ask a company administrator to add you."
        />
      </div>
    );
  }
  if (entries.length === 0) {
    return (
      <div data-testid="sidebar-nav-empty" className="overflow-hidden px-2 group-data-[collapsible=icon]:hidden">
        <EmptyState icon={LayoutGrid} title="No modules installed" description="Modules enabled for this instance will appear here." />
      </div>
    );
  }

  return (
    <SidebarGroup>
      <SidebarGroupLabel>Platform</SidebarGroupLabel>
      <SidebarMenu data-testid="sidebar-nav" aria-label="Modules">
        {entries.map((entry) => {
          const Icon = entry.icon ?? LayoutGrid;
          const isActive = activePathname === entry.href || (activePathname?.startsWith(`${entry.href}/`) ?? false);
          return (
            <SidebarMenuItem key={entry.moduleKey}>
              <SidebarMenuButton asChild isActive={isActive} tooltip={entry.label}>
                {/* Router Link, NOT a bare <a>: a raw anchor makes every
                    module click a FULL browser navigation — the whole SPA reboots, all in-memory
                    state (incl. the session composition cache) dies, and the user sees a hard
                    jump. Link renders the same <a role=link> the e2e suites locate, but
                    intercepts the click into a client-side route change. */}
                <Link to={entry.href}>
                  <Icon aria-hidden="true" />
                  <span>{entry.label}</span>
                </Link>
              </SidebarMenuButton>
              {entry.badge ? (
                <SidebarMenuBadge data-testid={`nav-badge-${entry.moduleKey}`}>
                  {entry.badge > 99 ? "99+" : entry.badge}
                </SidebarMenuBadge>
              ) : null}
            </SidebarMenuItem>
          );
        })}
      </SidebarMenu>
    </SidebarGroup>
  );
}
