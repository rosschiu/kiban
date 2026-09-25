// SPDX-License-Identifier: Apache-2.0

// The notification module's "inbox" route (frontend.manifest.json route id "inbox",
// path "" — the module's company-scoped default landing page, gated by the generic
// `notification.access` feature key — see modules/registry.ts's own comment on why not the
// fragment's fine-grained `notification.inbox.view`). Registered against
// `remoteExport: "InboxPage"` in modules/registry.ts.
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createNotificationClient, type NotificationMessage } from "./api";

export function InboxPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [messages, setMessages] = useState<NotificationMessage[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (id: string) => {
    try {
      const client = createNotificationClient(getShellSdk().apiClient);
      const page = await client.listInbox(id, 1, 50);
      setMessages(page.items);
      setError(null);
    } catch {
      setError("Could not load your inbox.");
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  async function handleMarkRead(messageId: string): Promise<void> {
    if (!companyId) return;
    const client = createNotificationClient(getShellSdk().apiClient);
    await client.markRead(companyId, messageId);
    void load(companyId);
  }

  if (!companyId) return null;

  return (
    <div className="flex flex-col gap-4" data-testid="notification-inbox-page">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-foreground">Inbox</h1>
        <a
          href={`/app/c/${encodeURIComponent(companyId)}/notification/channels`}
          className="text-sm text-muted-foreground underline underline-offset-2"
        >
          Manage channels
        </a>
      </div>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      {messages === null ? null : messages.length === 0 ? (
        <EmptyState title="No messages yet" description="Messages sent to channels you subscribe to will appear here." />
      ) : (
        <ul className="flex flex-col gap-2" data-testid="notification-inbox-list">
          {messages.map((message) => (
            <li key={message.id}>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between gap-2">
                    <span>{message.subjectLine}</span>
                    {message.readAt === null ? (
                      <span
                        data-testid={`notification-unread-${message.id}`}
                        className="rounded-full bg-primary px-2 py-0.5 text-xs font-medium text-primary-foreground"
                      >
                        Unread
                      </span>
                    ) : null}
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-2">
                  <p className="text-sm text-muted-foreground">{message.body}</p>
                  {message.readAt === null ? (
                    <Button type="button" size="sm" variant="outline" onClick={() => void handleMarkRead(message.id)}>
                      Mark read
                    </Button>
                  ) : (
                    <p className="text-xs text-muted-foreground">Read</p>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
