// SPDX-License-Identifier: Apache-2.0

// Thin, hand-written client for the notification module's own HTTP surface
// (modules/notification/openapi.yaml), built directly on the shared @rosschiu/kiban-sdk `ApiClient` the
// shell already uses everywhere else. This is
// intentionally NOT part of @rosschiu/kiban-sdk itself: the SDK ships only foundation-owned typed clients
// (org/capabilities/effectiveAccess/superadmin — web/sdk/src/index.ts); a module's own API
// surface is the module's own concern (a module owns its manifest, API and optional
// frontend), so notification gets its own thin wrapper here rather than the shared package
// growing a per-module client.
//
// `ApiClient.request<T>()` is sufficient to build this — no SDK change is needed. The pattern is
// a direct copy of web/sdk/src/org.ts's own shape (one function taking an `ApiClient`, returning
// an object of typed methods), so a module author following that file as a template needs
// nothing new from the platform.
import type { ApiClient, Page } from "@rosschiu/kiban-sdk";

export type NotificationChannelKind = "in_app" | "email" | "webhook";

export interface NotificationChannel {
  id: string;
  companyId: string;
  key: string;
  label: string;
  kind: NotificationChannelKind;
  target: string | null;
  createdAt: string;
}

export interface NotificationMessage {
  id: string;
  companyId: string;
  channelId: string;
  subjectLine: string;
  body: string;
  createdBy: string;
  createdAt: string;
  readAt: string | null;
}

export interface CreateChannelInput {
  key: string;
  label: string;
  kind: NotificationChannelKind;
  target?: string | null;
}

export interface SendMessageInput {
  channelId: string;
  subjectLine: string;
  body: string;
}

export interface NotificationClient {
  listChannels(companyId: string, page?: number, pageSize?: number): Promise<Page<NotificationChannel>>;
  createChannel(companyId: string, input: CreateChannelInput): Promise<NotificationChannel>;
  subscribeSelf(companyId: string, channelId: string): Promise<void>;
  unsubscribeSelf(companyId: string, channelId: string): Promise<void>;
  listInbox(companyId: string, page?: number, pageSize?: number): Promise<Page<NotificationMessage>>;
  sendMessage(companyId: string, input: SendMessageInput, idempotencyKey?: string): Promise<NotificationMessage>;
  markRead(companyId: string, messageId: string): Promise<NotificationMessage>;
}

function companyBase(companyId: string): string {
  return `/api/notification/v1/companies/${encodeURIComponent(companyId)}`;
}

export function createNotificationClient(client: ApiClient): NotificationClient {
  return {
    listChannels: (companyId, page, pageSize) =>
      client.request(`${companyBase(companyId)}/channels`, { query: { page, pageSize } }),

    createChannel: (companyId, input) =>
      client.request(`${companyBase(companyId)}/channels`, { method: "POST", body: input }),

    subscribeSelf: (companyId, channelId) =>
      client.request(`${companyBase(companyId)}/channels/${encodeURIComponent(channelId)}/subscriptions`, { method: "POST" }),

    unsubscribeSelf: (companyId, channelId) =>
      client.request(`${companyBase(companyId)}/channels/${encodeURIComponent(channelId)}/subscriptions/me`, {
        method: "DELETE",
      }),

    listInbox: (companyId, page, pageSize) =>
      client.request(`${companyBase(companyId)}/messages`, { query: { page, pageSize } }),

    sendMessage: (companyId, input, idempotencyKey) =>
      client.request(`${companyBase(companyId)}/messages`, {
        method: "POST",
        body: input,
        ...(idempotencyKey ? { headers: { "Idempotency-Key": idempotencyKey } } : {}),
      }),

    markRead: (companyId, messageId) =>
      client.request(`${companyBase(companyId)}/messages/${encodeURIComponent(messageId)}/read`, { method: "POST" }),
  };
}
