// SPDX-License-Identifier: Apache-2.0

import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { useNotificationUnreadCount } = await import("../../../src/modules/notification/use-unread-count");

function page(items: { readAt: string | null }[]) {
  return { items, total: items.length, page: 1, pageSize: 100, totalPages: 1 };
}

describe("useNotificationUnreadCount", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("returns undefined with no active company, and never fetches", () => {
    const { result } = renderHook(() => useNotificationUnreadCount(null));
    expect(result.current).toBeUndefined();
    expect(request).not.toHaveBeenCalled();
  });

  it("counts messages with readAt === null once the fetch resolves", async () => {
    request.mockResolvedValue(page([{ readAt: null }, { readAt: "2026-01-01T00:00:00Z" }, { readAt: null }]));
    const { result } = renderHook(() => useNotificationUnreadCount("company-a"));
    await waitFor(() => expect(result.current).toBe(2));
    expect(request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages", {
      query: { page: 1, pageSize: 100 },
    });
  });

  it("fails closed to undefined when the fetch rejects", async () => {
    request.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useNotificationUnreadCount("company-a"));
    await waitFor(() => expect(request).toHaveBeenCalled());
    await waitFor(() => expect(result.current).toBeUndefined());
  });

  it("polls again on a fixed interval, refreshing the count", async () => {
    const setIntervalSpy = vi.spyOn(global, "setInterval");
    request.mockResolvedValueOnce(page([{ readAt: null }])).mockResolvedValueOnce(page([]));
    const { result } = renderHook(() => useNotificationUnreadCount("company-a"));
    await waitFor(() => expect(result.current).toBe(1));

    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 4000);
    const onInterval = setIntervalSpy.mock.calls[0]![0] as () => void;
    onInterval();

    await waitFor(() => expect(result.current).toBe(0));
    expect(request).toHaveBeenCalledTimes(2);
    setIntervalSpy.mockRestore();
  });

  it("resets to undefined and stops polling the old company when companyId changes to null", async () => {
    request.mockResolvedValue(page([{ readAt: null }]));
    const { result, rerender } = renderHook(({ companyId }) => useNotificationUnreadCount(companyId), {
      initialProps: { companyId: "company-a" as string | null },
    });
    await waitFor(() => expect(result.current).toBe(1));

    rerender({ companyId: null });
    expect(result.current).toBeUndefined();
  });
});
