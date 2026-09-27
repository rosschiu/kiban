// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { localModuleCatalog, localModuleRegistry } from "../../src/modules/registry";

// Registry entries: notification, timesheet, docs (the fine-grained-sharing showcase) and
// helpdesk (the workflow/tier showcase). The empty-registry resolver/nav plumbing is covered
// separately by resolver.test.ts / nav/*.test.ts.
describe("localModuleRegistry (notification, timesheet, docs, helpdesk)", () => {
  it("registers exactly the notification, timesheet, docs, and helpdesk modules", () => {
    expect(Object.keys(localModuleRegistry)).toEqual(["notification", "timesheet", "docs", "helpdesk"]);
  });

  it("derives a resolver catalog with all four modules' routes", () => {
    expect(localModuleCatalog()).toEqual([
      {
        moduleKey: "notification",
        scope: "company",
        routes: [
          { id: "inbox", path: "", featureKey: "notification.access", remoteExport: "InboxPage" },
          { id: "channels", path: "channels", featureKey: "notification.access", remoteExport: "ChannelsPage" },
        ],
      },
      {
        moduleKey: "timesheet",
        scope: "company",
        routes: [
          { id: "entries", path: "", featureKey: "timesheet.access", remoteExport: "EntriesPage" },
          { id: "submissions", path: "submissions", featureKey: "timesheet.access", remoteExport: "SubmissionsPage" },
          { id: "approvals", path: "approvals", featureKey: "timesheet.access", remoteExport: "ApprovalsPage" },
        ],
      },
      {
        moduleKey: "docs",
        scope: "company",
        routes: [
          { id: "documents", path: "", featureKey: "docs.access", remoteExport: "DocumentsListPage" },
          { id: "document", path: "documents/:docId", featureKey: "docs.access", remoteExport: "DocumentPage" },
          { id: "admin", path: "admin", featureKey: "docs.access", remoteExport: "AdminPage" },
        ],
      },
      {
        moduleKey: "helpdesk",
        scope: "company",
        routes: [
          { id: "my-tickets", path: "", featureKey: "helpdesk.access", remoteExport: "MyTicketsPage" },
          { id: "ticket-detail", path: "tickets/:ticketId", featureKey: "helpdesk.access", remoteExport: "TicketDetailPage" },
          { id: "all-tickets", path: "all", featureKey: "helpdesk.access", remoteExport: "AllTicketsPage" },
          { id: "agents-admin", path: "agents", featureKey: "helpdesk.access", remoteExport: "AgentsAdminPage" },
        ],
      },
    ]);
  });

  it("registers a lazy page component for every route's remoteExport", () => {
    for (const mod of Object.values(localModuleRegistry)) {
      for (const route of mod.catalog.routes) {
        expect(mod.pages[route.remoteExport]).toBeDefined();
      }
    }
  });

  it("supplies nav metadata (label/navOrder/icon)", () => {
    const notification = localModuleRegistry["notification"]!;
    expect(notification.nav.label).toBe("Notification");
    expect(notification.nav.navOrder).toBe(10);
    expect(notification.nav.icon).toBeDefined();

    const timesheet = localModuleRegistry["timesheet"]!;
    expect(timesheet.nav.label).toBe("Timesheet");
    expect(timesheet.nav.navOrder).toBe(20);
    expect(timesheet.nav.icon).toBeDefined();

    const docs = localModuleRegistry["docs"]!;
    expect(docs.nav.label).toBe("Docs");
    expect(docs.nav.navOrder).toBe(30);
    expect(docs.nav.icon).toBeDefined();

    const helpdesk = localModuleRegistry["helpdesk"]!;
    expect(helpdesk.nav.label).toBe("Helpdesk");
    expect(helpdesk.nav.navOrder).toBe(40);
    expect(helpdesk.nav.icon).toBeDefined();
  });

  it("supplies an unread-count hook for notification only", () => {
    const notification = localModuleRegistry["notification"]!;
    expect(typeof notification.useUnreadCount).toBe("function");

    const timesheet = localModuleRegistry["timesheet"]!;
    expect(timesheet.useUnreadCount).toBeUndefined();

    const docs = localModuleRegistry["docs"]!;
    expect(docs.useUnreadCount).toBeUndefined();

    const helpdesk = localModuleRegistry["helpdesk"]!;
    expect(helpdesk.useUnreadCount).toBeUndefined();
  });
});
