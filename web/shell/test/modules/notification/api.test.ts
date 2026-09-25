// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createNotificationClient } from "../../../src/modules/notification/api";

function fakeClient() {
  return { baseUrl: "https://gw.example", request: vi.fn().mockResolvedValue(undefined) };
}

describe("createNotificationClient", () => {
  it("lists channels with pagination query params", async () => {
    const client = fakeClient();
    await createNotificationClient(client).listChannels("company-a", 2, 25);
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/channels", {
      query: { page: 2, pageSize: 25 },
    });
  });

  it("creates a channel via POST with the input as the body", async () => {
    const client = fakeClient();
    const input = { key: "k", label: "L", kind: "in_app" as const };
    await createNotificationClient(client).createChannel("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/channels", {
      method: "POST",
      body: input,
    });
  });

  it("subscribes self via POST to the channel's subscriptions collection", async () => {
    const client = fakeClient();
    await createNotificationClient(client).subscribeSelf("company-a", "chan-1");
    expect(client.request).toHaveBeenCalledWith(
      "/api/notification/v1/companies/company-a/channels/chan-1/subscriptions",
      { method: "POST" },
    );
  });

  it("unsubscribes self via DELETE to the /me subscription", async () => {
    const client = fakeClient();
    await createNotificationClient(client).unsubscribeSelf("company-a", "chan-1");
    expect(client.request).toHaveBeenCalledWith(
      "/api/notification/v1/companies/company-a/channels/chan-1/subscriptions/me",
      { method: "DELETE" },
    );
  });

  it("lists the inbox with pagination query params", async () => {
    const client = fakeClient();
    await createNotificationClient(client).listInbox("company-a", 1, 50);
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages", {
      query: { page: 1, pageSize: 50 },
    });
  });

  it("sends a message without an Idempotency-Key header when none is given", async () => {
    const client = fakeClient();
    const input = { channelId: "chan-1", subjectLine: "Hi", body: "World" };
    await createNotificationClient(client).sendMessage("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages", {
      method: "POST",
      body: input,
    });
  });

  it("sends a message with an Idempotency-Key header when given", async () => {
    const client = fakeClient();
    const input = { channelId: "chan-1", subjectLine: "Hi", body: "World" };
    await createNotificationClient(client).sendMessage("company-a", input, "idem-1");
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages", {
      method: "POST",
      body: input,
      headers: { "Idempotency-Key": "idem-1" },
    });
  });

  it("marks a message read via POST to its /read sub-resource", async () => {
    const client = fakeClient();
    await createNotificationClient(client).markRead("company-a", "msg-1");
    expect(client.request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages/msg-1/read", {
      method: "POST",
    });
  });

  it("URI-encodes path segments", async () => {
    const client = fakeClient();
    await createNotificationClient(client).markRead("company a/b", "msg 1");
    expect(client.request).toHaveBeenCalledWith(
      "/api/notification/v1/companies/company%20a%2Fb/messages/msg%201/read",
      { method: "POST" },
    );
  });
});
