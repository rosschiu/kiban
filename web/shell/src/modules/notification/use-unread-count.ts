// SPDX-License-Identifier: Apache-2.0

// Sidebar unread-badge data source. Polls the caller's own
// inbox for the active company and returns how many messages have `readAt === null`. v1's
// openapi.yaml has no unread-COUNT-only endpoint (only the full inbox page list; in-app delivery
// is poll-only in v1), so this fetches one generously-sized page and
// counts client-side; acceptable at v1's scope — a dedicated unread-count endpoint is the
// upgrade if inbox volume ever outgrows a single page.
import { useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import { createNotificationClient } from "./api";

const POLL_INTERVAL_MS = 4000;
const UNREAD_PAGE_SIZE = 100;

/** Returns `undefined` while unauthenticated, with no active company, or whenever the fetch
 * fails — fail-closed, same posture as nav/module-access.ts (never throws into the sidebar). */
export function useNotificationUnreadCount(companyId: string | null): number | undefined {
  const [count, setCount] = useState<number | undefined>(undefined);

  useEffect(() => {
    if (!companyId) {
      setCount(undefined);
      return;
    }

    let cancelled = false;
    const client = createNotificationClient(getShellSdk().apiClient);

    async function poll(id: string): Promise<void> {
      try {
        const page = await client.listInbox(id, 1, UNREAD_PAGE_SIZE);
        if (!cancelled) setCount(page.items.filter((message) => message.readAt === null).length);
      } catch {
        if (!cancelled) setCount(undefined);
      }
    }

    void poll(companyId);
    const interval = setInterval(() => void poll(companyId), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [companyId]);

  return count;
}
