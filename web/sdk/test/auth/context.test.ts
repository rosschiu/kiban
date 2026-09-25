// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createSessionContext } from "../../src/auth/context.js";
import { createMemoryStorage } from "../../src/storage.js";

describe("createSessionContext", () => {
  it("defaults activeCompanyId to null and preferences to {}", () => {
    const ctx = createSessionContext({ storage: createMemoryStorage() });
    expect(ctx.getActiveCompanyId()).toBeNull();
    expect(ctx.getPreferences()).toEqual({});
  });

  it("persists activeCompanyId through the injected storage", () => {
    const storage = createMemoryStorage();
    const ctx = createSessionContext({ storage });

    ctx.setActiveCompanyId("company-1");

    expect(ctx.getActiveCompanyId()).toBe("company-1");
    expect(storage.getItem("kiban.activeCompanyId")).toBe("company-1");

    ctx.setActiveCompanyId(null);
    expect(ctx.getActiveCompanyId()).toBeNull();
    expect(storage.getItem("kiban.activeCompanyId")).toBeNull();
  });

  it("merges preferences under setPreference", () => {
    const ctx = createSessionContext({ storage: createMemoryStorage() });

    ctx.setPreference("theme", "dark");
    ctx.setPreference("locale", "en");

    expect(ctx.getPreferences()).toEqual({ theme: "dark", locale: "en" });
    expect(ctx.getPreference("theme")).toBe("dark");
    expect(ctx.getPreference("missing")).toBeUndefined();
  });

  it("clear() resets both activeCompanyId and preferences", () => {
    const ctx = createSessionContext({ storage: createMemoryStorage() });
    ctx.setActiveCompanyId("company-1");
    ctx.setPreference("theme", "dark");

    ctx.clear();

    expect(ctx.getActiveCompanyId()).toBeNull();
    expect(ctx.getPreferences()).toEqual({});
  });

  it("notifies subscribers on every mutation and honors unsubscribe", () => {
    const ctx = createSessionContext({ storage: createMemoryStorage() });
    const listener = vi.fn();
    const unsubscribe = ctx.subscribe(listener);

    ctx.setActiveCompanyId("company-1");
    ctx.setPreference("theme", "dark");
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    ctx.setActiveCompanyId("company-2");
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("uses the configured storageKeyPrefix", () => {
    const storage = createMemoryStorage();
    const ctx = createSessionContext({ storage, storageKeyPrefix: "myapp." });

    ctx.setActiveCompanyId("company-1");

    expect(storage.getItem("myapp.activeCompanyId")).toBe("company-1");
    expect(storage.getItem("kiban.activeCompanyId")).toBeNull();
  });

  it("getPreferences() recovers to {} when the stored value is malformed JSON", () => {
    const storage = createMemoryStorage();
    storage.setItem("kiban.preferences", "{not valid json");
    const ctx = createSessionContext({ storage });

    expect(ctx.getPreferences()).toEqual({});
    expect(ctx.getPreference("anything")).toBeUndefined();
  });

  it("two independently-created contexts over the same storage see each other's writes", () => {
    const storage = createMemoryStorage();
    const a = createSessionContext({ storage });
    const b = createSessionContext({ storage });

    a.setActiveCompanyId("company-1");

    expect(b.getActiveCompanyId()).toBe("company-1");
  });
});
