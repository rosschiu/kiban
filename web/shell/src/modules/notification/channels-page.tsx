// SPDX-License-Identifier: Apache-2.0

// The notification module's "channels" route (frontend.manifest.json route id
// "channels", gated by the generic `notification.access` feature key — see modules/registry.ts's
// own comment on why not the fragment's fine-grained `notification.channels.manage`). Create +
// list + self-subscribe — the
// minimum needed to make a channel usable from the module's own UI; message SEND has no UI form
// (the e2e journey drives "send" through the API directly), and there is no
// preference/digest UI beyond mute-per-channel.
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createNotificationClient, type NotificationChannel } from "./api";

export function ChannelsPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [channels, setChannels] = useState<NotificationChannel[] | null>(null);
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [subscribed, setSubscribed] = useState<Record<string, boolean>>({});

  const load = useCallback(async (id: string) => {
    try {
      const client = createNotificationClient(getShellSdk().apiClient);
      const page = await client.listChannels(id, 1, 100);
      setChannels(page.items);
      setError(null);
    } catch {
      setError("Could not load channels.");
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  async function handleCreate(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!companyId || !key.trim() || !label.trim()) return;
    try {
      const client = createNotificationClient(getShellSdk().apiClient);
      await client.createChannel(companyId, { key: key.trim(), label: label.trim(), kind: "in_app" });
      setKey("");
      setLabel("");
      void load(companyId);
    } catch {
      setError("Could not create the channel.");
    }
  }

  async function handleSubscribe(channelId: string): Promise<void> {
    if (!companyId) return;
    try {
      const client = createNotificationClient(getShellSdk().apiClient);
      await client.subscribeSelf(companyId, channelId);
      setSubscribed((prev) => ({ ...prev, [channelId]: true }));
    } catch {
      setError("Could not subscribe to the channel.");
    }
  }

  if (!companyId) return null;

  return (
    <div className="flex flex-col gap-4" data-testid="notification-channels-page">
      <h1 className="text-lg font-semibold text-foreground">Notification channels</h1>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>New channel</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="flex flex-wrap items-end gap-2" onSubmit={(event) => void handleCreate(event)}>
            <label className="flex flex-col gap-1 text-sm">
              Key
              <input
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                value={key}
                onChange={(event) => setKey(event.target.value)}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Label
              <input
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
              />
            </label>
            <Button type="submit" size="sm">
              Create
            </Button>
          </form>
        </CardContent>
      </Card>

      {channels === null ? null : channels.length === 0 ? (
        <EmptyState title="No channels yet" description="Create a channel to start sending notifications." />
      ) : (
        <ul className="flex flex-col gap-2" data-testid="notification-channels-list">
          {channels.map((channel) => (
            <li
              key={channel.id}
              data-testid={`notification-channel-${channel.id}`}
              className="flex items-center justify-between rounded-md border border-border px-3 py-2"
            >
              <span>
                {channel.label} <span className="text-xs text-muted-foreground">({channel.key})</span>
              </span>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={subscribed[channel.id] === true}
                onClick={() => void handleSubscribe(channel.id)}
              >
                {subscribed[channel.id] === true ? "Subscribed" : "Subscribe"}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
