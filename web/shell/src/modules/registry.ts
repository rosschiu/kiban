// SPDX-License-Identifier: Apache-2.0

// The local module registry: maps moduleKey -> lazy React component. Nav/route hosts are
// catalog-driven with NO hardcoded module list; every module registers its entry here following
// the same pattern. Remote module loading is not supported — only ever local,
// statically-imported lazy components (source vendored under ./notification/ — see
// modules/notification/frontend/frontend.manifest.json's own comment for why).
import type { LucideIcon } from "lucide-react";
import { BellIcon, ClockIcon, FileTextIcon, LifeBuoyIcon } from "lucide-react";
import { lazy, type ComponentType, type LazyExoticComponent } from "react";
import { assertValidModuleCatalog, type ModuleCatalog, type ModulePageContext } from "../resolver/resolver";
import { useNotificationUnreadCount } from "./notification/use-unread-count";

/** Sidebar display metadata for a registered module (nav composition —
 * compose.ts's `computeNavEntries`). The registry catalog (platform CatalogEntry, from the SDK)
 * has no navOrder/icon fields of its own — Kiban's catalog is deliberately lean
 * (no per-instance nav config), so each locally-registered module supplies its own ordering/icon
 * the same way it supplies its own routes/pages: this is client code the module ships, not
 * server config. `label` is a fallback only — CatalogEntry.displayName wins when the platform
 * catalog knows the module (server is the naming source of truth). */
export interface ModuleNavDescriptor {
  label: string;
  navOrder: number;
  icon?: LucideIcon;
}

/** One registered module's catalog metadata (routes/scope/feature keys — resolver input) plus
 * the lazy component each route's `remoteExport` resolves to. */
export interface RegisteredModule {
  catalog: ModuleCatalog[number];
  nav: ModuleNavDescriptor;
  /** remoteExport -> lazy component rendering that page, given the resolved page context. */
  pages: Readonly<Record<string, LazyExoticComponent<ComponentType<{ context: ModulePageContext }>>>>;
  /** Optional unread/activity badge count for the sidebar entry,
   * given the active company id (or null for a global-scope module). Called
   * unconditionally for every registry entry that declares it (nav/nav-badges.ts) — safe because
   * `localModuleRegistry` is a module-level constant: which entries declare `useUnreadCount`
   * never changes across renders, so the Rules of Hooks are satisfied despite the lookup living
   * in a loop. Returns `undefined`/`0` for "no badge". */
  useUnreadCount?: (companyId: string | null) => number | undefined;
}

/** moduleKey -> RegisteredModule. */
export const localModuleRegistry: Readonly<Record<string, RegisteredModule>> = {
  notification: {
    catalog: {
      moduleKey: "notification",
      scope: "company",
      routes: [
        // path "" is the module's default landing page — compose.ts's `computeNavEntries` links
        // the sidebar entry straight to the bare module root (`/app/c/:companyId/notification`,
        // no route suffix), which normalizeModulePath resolves to zero segments; only a route
        // whose own path also normalizes to zero segments can match that.
        //
        // featureKey "notification.access" (NOT the fine-grained
        // "notification.inbox.view"/"notification.channels.manage" the module's own
        // authz.fragment.json declares) — deliberate: no install path
        // exists to load a module's authz fragment into the live authz engine, so those
        // fragment-declared keys are NEVER granted to anyone. `internal/authz/summary.go` DOES
        // synthesize a real, granted "<moduleKey>.access" feature key per enabled module at
        // company scope (independent of fragment loading) — the resolver's featureKey gate
        // (resolver.ts Stage 5) is checked against the caller's real EffectiveAccessSummary, so
        // gating on the fragment's aspirational keys would make these routes permanently
        // unreachable by anyone.
        { id: "inbox", path: "", featureKey: "notification.access", remoteExport: "InboxPage" },
        { id: "channels", path: "channels", featureKey: "notification.access", remoteExport: "ChannelsPage" },
      ],
    },
    nav: { label: "Notification", navOrder: 10, icon: BellIcon },
    pages: {
      InboxPage: lazy(() => import("./notification/inbox-page").then((mod) => ({ default: mod.InboxPage }))),
      ChannelsPage: lazy(() => import("./notification/channels-page").then((mod) => ({ default: mod.ChannelsPage }))),
    },
    useUnreadCount: useNotificationUnreadCount,
  },
  // The timesheet module. Same "featureKey ==
  // <moduleKey>.access" convention as notification's own entry above —
  // the fragment's fine-grained feature keys (timesheet.entries.manage-own etc.) aren't gateable
  // from the frontend yet for the same documented reason.
  timesheet: {
    catalog: {
      moduleKey: "timesheet",
      scope: "company",
      routes: [
        { id: "entries", path: "", featureKey: "timesheet.access", remoteExport: "EntriesPage" },
        { id: "submissions", path: "submissions", featureKey: "timesheet.access", remoteExport: "SubmissionsPage" },
        { id: "approvals", path: "approvals", featureKey: "timesheet.access", remoteExport: "ApprovalsPage" },
      ],
    },
    nav: { label: "Timesheet", navOrder: 20, icon: ClockIcon },
    pages: {
      EntriesPage: lazy(() => import("./timesheet/entries-page").then((mod) => ({ default: mod.EntriesPage }))),
      SubmissionsPage: lazy(() => import("./timesheet/submissions-page").then((mod) => ({ default: mod.SubmissionsPage }))),
      ApprovalsPage: lazy(() => import("./timesheet/approvals-page").then((mod) => ({ default: mod.ApprovalsPage }))),
    },
  },
  // The docs module, the fine-grained-sharing showcase. Same "featureKey ==
  // <moduleKey>.access" convention as notification's/timesheet's own entries above —
  // per-document viewer/editor access is enforced server-side via the
  // object-mode authz check, not by this frontend route gate.
  docs: {
    catalog: {
      moduleKey: "docs",
      scope: "company",
      routes: [
        { id: "documents", path: "", featureKey: "docs.access", remoteExport: "DocumentsListPage" },
        { id: "document", path: "documents/:docId", featureKey: "docs.access", remoteExport: "DocumentPage" },
        { id: "admin", path: "admin", featureKey: "docs.access", remoteExport: "AdminPage" },
      ],
    },
    nav: { label: "Docs", navOrder: 30, icon: FileTextIcon },
    pages: {
      DocumentsListPage: lazy(() => import("./docs/documents-list-page").then((mod) => ({ default: mod.DocumentsListPage }))),
      DocumentPage: lazy(() => import("./docs/document-page").then((mod) => ({ default: mod.DocumentPage }))),
      AdminPage: lazy(() => import("./docs/admin-page").then((mod) => ({ default: mod.AdminPage }))),
    },
  },
  // The helpdesk module, the workflow/tier showcase. Same "featureKey ==
  // <moduleKey>.access" convention as notification's/timesheet's/docs's own entries above —
  // the tier contrast (reporter never sees the All-tickets nav) is computed
  // INSIDE the module's own tree from a dedicated GET .../me read, not by this route-level gate
  // (see web/shell/src/modules/helpdesk/tier.ts).
  helpdesk: {
    catalog: {
      moduleKey: "helpdesk",
      scope: "company",
      routes: [
        { id: "my-tickets", path: "", featureKey: "helpdesk.access", remoteExport: "MyTicketsPage" },
        { id: "ticket-detail", path: "tickets/:ticketId", featureKey: "helpdesk.access", remoteExport: "TicketDetailPage" },
        { id: "all-tickets", path: "all", featureKey: "helpdesk.access", remoteExport: "AllTicketsPage" },
        { id: "agents-admin", path: "agents", featureKey: "helpdesk.access", remoteExport: "AgentsAdminPage" },
      ],
    },
    nav: { label: "Helpdesk", navOrder: 40, icon: LifeBuoyIcon },
    pages: {
      MyTicketsPage: lazy(() => import("./helpdesk/my-tickets-page").then((mod) => ({ default: mod.MyTicketsPage }))),
      TicketDetailPage: lazy(() => import("./helpdesk/ticket-detail-page").then((mod) => ({ default: mod.TicketDetailPage }))),
      AllTicketsPage: lazy(() => import("./helpdesk/all-tickets-page").then((mod) => ({ default: mod.AllTicketsPage }))),
      AgentsAdminPage: lazy(() => import("./helpdesk/agents-admin-page").then((mod) => ({ default: mod.AgentsAdminPage }))),
    },
  },
};

/** Derived resolver input — every registered module's catalog entry, in registration order. */
export function localModuleCatalog(): ModuleCatalog {
  return Object.values(localModuleRegistry).map((entry) => entry.catalog);
}

// Fail fast on a malformed local catalog (resolver.ts's
// own doc comment: "Call this once ... at catalog-load time in modules/registry.ts").
assertValidModuleCatalog(localModuleCatalog());
