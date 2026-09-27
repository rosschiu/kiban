// SPDX-License-Identifier: Apache-2.0

import { createMemoryStorage } from "@rosschiu/kiban-sdk";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ThemeToggle } from "../../src/ui/theme-toggle";

describe("ThemeToggle", () => {
  beforeEach(() => {
    document.documentElement.classList.remove("dark");
  });
  afterEach(() => {
    document.documentElement.classList.remove("dark");
  });

  it("defaults to light and toggles the html.dark class + persists the choice", async () => {
    const storage = createMemoryStorage();
    const user = userEvent.setup();
    render(<ThemeToggle storage={storage} />);
    expect(document.documentElement.classList.contains("dark")).toBe(false);

    await user.click(screen.getByRole("button"));
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(storage.getItem("kiban.theme")).toBe("dark");

    await user.click(screen.getByRole("button"));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(storage.getItem("kiban.theme")).toBe("light");
  });

  it("reads a previously persisted theme on mount", () => {
    const storage = createMemoryStorage();
    storage.setItem("kiban.theme", "dark");
    render(<ThemeToggle storage={storage} />);
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("renders using the default (browser/memory-fallback) storage when none is injected", () => {
    render(<ThemeToggle />);
    expect(screen.getByRole("button")).toBeInTheDocument();
  });
});
