// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DemoBanner } from "../../src/ui/demo-banner";

const useDemoMode = vi.fn();
vi.mock("../../src/hooks/use-demo-mode", () => ({ useDemoMode: () => useDemoMode() }));

describe("DemoBanner", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });
  afterEach(() => {
    vi.resetAllMocks();
  });

  it("renders nothing when demo mode is off", () => {
    useDemoMode.mockReturnValue(false);
    render(<DemoBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the banner text when demo mode is on", () => {
    useDemoMode.mockReturnValue(true);
    render(<DemoBanner />);
    expect(screen.getByText(/public demo/i)).toBeInTheDocument();
    expect(screen.getByText(/resets nightly/i)).toBeInTheDocument();
  });

  it("dismisses on click and remembers the dismissal for the session", async () => {
    useDemoMode.mockReturnValue(true);
    const user = userEvent.setup();
    const { unmount } = render(<DemoBanner />);
    expect(screen.getByRole("status")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /dismiss demo banner/i }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(window.sessionStorage.getItem("kiban:demo-banner-dismissed")).toBe("true");

    // a fresh mount in the same "session" (sessionStorage untouched) stays dismissed
    unmount();
    render(<DemoBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("stays dismissed across remounts once sessionStorage already carries the flag", () => {
    window.sessionStorage.setItem("kiban:demo-banner-dismissed", "true");
    useDemoMode.mockReturnValue(true);
    render(<DemoBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("never renders when demo mode is off even if previously dismissed", () => {
    window.sessionStorage.setItem("kiban:demo-banner-dismissed", "true");
    useDemoMode.mockReturnValue(false);
    render(<DemoBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
