// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryStorage, defaultLocalStorage, defaultSessionStorage } from "../src/storage.js";

describe("createMemoryStorage", () => {
  it("round-trips get/set/remove and returns null for missing keys", () => {
    const storage = createMemoryStorage();

    expect(storage.getItem("k")).toBeNull();
    storage.setItem("k", "v");
    expect(storage.getItem("k")).toBe("v");
    storage.removeItem("k");
    expect(storage.getItem("k")).toBeNull();
  });
});

describe("defaultSessionStorage / defaultLocalStorage — browser adapter delegation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("defaultSessionStorage() delegates to the global sessionStorage when present", () => {
    const backing = new Map<string, string>();
    const fakeSessionStorage = {
      getItem: vi.fn((key: string) => backing.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        backing.set(key, value);
      }),
      removeItem: vi.fn((key: string) => {
        backing.delete(key);
      })
    };
    vi.stubGlobal("sessionStorage", fakeSessionStorage);

    const adapter = defaultSessionStorage();
    adapter.setItem("a", "1");
    expect(fakeSessionStorage.setItem).toHaveBeenCalledWith("a", "1");
    expect(adapter.getItem("a")).toBe("1");
    expect(fakeSessionStorage.getItem).toHaveBeenCalledWith("a");
    adapter.removeItem("a");
    expect(fakeSessionStorage.removeItem).toHaveBeenCalledWith("a");
  });

  it("defaultSessionStorage() falls back to an in-memory store when sessionStorage is unavailable", () => {
    vi.stubGlobal("sessionStorage", undefined);

    const adapter = defaultSessionStorage();
    adapter.setItem("a", "1");
    expect(adapter.getItem("a")).toBe("1");
  });

  it("defaultLocalStorage() delegates to the global localStorage when present", () => {
    const backing = new Map<string, string>();
    const fakeLocalStorage = {
      getItem: vi.fn((key: string) => backing.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        backing.set(key, value);
      }),
      removeItem: vi.fn((key: string) => {
        backing.delete(key);
      })
    };
    vi.stubGlobal("localStorage", fakeLocalStorage);

    const adapter = defaultLocalStorage();
    adapter.setItem("b", "2");
    expect(fakeLocalStorage.setItem).toHaveBeenCalledWith("b", "2");
    expect(adapter.getItem("b")).toBe("2");
    adapter.removeItem("b");
    expect(fakeLocalStorage.removeItem).toHaveBeenCalledWith("b");
  });

  it("defaultLocalStorage() falls back to an in-memory store when localStorage is unavailable", () => {
    vi.stubGlobal("localStorage", undefined);

    const adapter = defaultLocalStorage();
    adapter.setItem("b", "2");
    expect(adapter.getItem("b")).toBe("2");
  });
});
