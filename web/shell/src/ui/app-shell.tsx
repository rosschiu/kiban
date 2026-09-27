// SPDX-License-Identifier: Apache-2.0

import { LogOut } from "lucide-react";
import type { ReactNode } from "react";
import { useLocation } from "@tanstack/react-router";
import { useShellSession } from "../auth/session-context";
import { decodeUserProfile } from "../auth/user-profile";
import { CompanySwitcher, type CompanySwitcherProps } from "../nav/company-switcher";
import { NavUser } from "../nav/nav-user";
import { type NavEntry, SidebarNav } from "../nav/sidebar-nav";
import { Button } from "./button";
import { DemoBanner } from "./demo-banner";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarProvider,
  SidebarRail,
} from "./sidebar";
import { SiteHeader } from "./site-header";
import { ThemeToggle } from "./theme-toggle";

export interface AppShellProps {
  /** See SidebarNav — empty by default until the composed catalog resolves. */
  navEntries?: readonly NavEntry[];
  /** See SidebarNav.ready — false renders the loading skeleton instead of the empty state. */
  navReady?: boolean;
  /** See SidebarNav.unavailable — a service outage message rendered instead of the empty state. */
  navUnavailable?: string;
  /** See CompanySwitcher — omitted (or a company-less caller) renders no switcher at all. */
  companySwitcher?: CompanySwitcherProps;
  children: ReactNode;
}

/** The guarded app's outer chrome, in shadcn's sidebar-07 shape:
 * SidebarProvider (height-locked, pane scrolling) → Sidebar [Header=company switcher,
 * Content=nav, Footer=NavUser, Rail] + (SiteHeader + SidebarInset). Everything under `/app`
 * renders through this. */
export function AppShell({ navEntries = [], navReady = true, navUnavailable, companySwitcher, children }: AppShellProps) {
  const { logout, session } = useShellSession();
  const location = useLocation();
  const profile = decodeUserProfile(session.getTokens()?.idToken ?? null);

  return (
    <SidebarProvider className="h-svh">
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-1.5">
            <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground text-sm font-semibold">
              K
            </div>
            <span className="truncate text-sm font-semibold tracking-tight group-data-[collapsible=icon]:hidden">Kiban</span>
          </div>
          {companySwitcher ? (
            <div className="overflow-hidden group-data-[collapsible=icon]:hidden">
              <CompanySwitcher {...companySwitcher} />
            </div>
          ) : null}
        </SidebarHeader>
        <SidebarContent>
          <SidebarNav
            entries={navEntries}
            ready={navReady}
            unavailable={navUnavailable}
            hasCompanies={companySwitcher ? companySwitcher.companies.length > 0 : true}
            activePathname={location.pathname}
          />
        </SidebarContent>
        <SidebarFooter>
          <NavUser
            user={{
              name: profile?.name ?? "Signed in",
              email: profile?.email ?? "",
              avatar: profile?.picture ?? null,
            }}
            onSignOut={logout}
          />
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset>
        <SiteHeader
          items={[{ label: "Overview" }]}
          actions={
            <>
              <ThemeToggle />
              <Button type="button" variant="ghost" size="sm" onClick={logout}>
                <LogOut className="size-4" aria-hidden="true" data-icon="inline-start" />
                Log out
              </Button>
            </>
          }
        />
        <DemoBanner />
        <main data-slot="page-frame" className="min-h-0 flex-1 overflow-auto p-6">
          {children}
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
