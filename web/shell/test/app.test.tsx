// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const fakeSession = {
  login: vi.fn().mockResolvedValue(undefined),
  buildLoginUrl: vi.fn(),
  handleCallback: vi.fn(),
  getAccessToken: vi.fn().mockReturnValue(null as string | null),
  refresh: vi.fn(),
  logout: vi.fn(),
  getTokens: vi.fn(),
  isAuthenticated: vi.fn().mockReturnValue(false),
};

vi.mock("../src/auth/sdk", () => ({
  getShellSdk: () => ({
    session: fakeSession,
    // DemoBanner's useDemoMode hook now calls apiClient.request() on every mount
    // (GET /api/platform/demo-mode) — the default vi.fn() (returns undefined) crashed this
    // smoke test with "Cannot read properties of undefined (reading 'then')" the moment
    // AppShell rendered. Resolves to demo-mode-off, matching this fixture's own non-demo intent
    // (nothing here should show the banner).
    apiClient: { baseUrl: "https://gateway.invalid", request: vi.fn().mockResolvedValue({ enabled: false }) },
  }),
  // session-context.tsx subscribes to this on mount (mid-journey
  // silent-refresh-failure notification) — a no-op subscription (never fires) is the correct
  // fake here, same posture as every other unused hook in these fixtures.
  onShellSessionInvalidated: () => () => {},
}));

const { App } = await import("../src/app");

describe("App (full provider + router wiring smoke test)", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/");
  });

  it("redirects an unauthenticated visitor from / to the login page", async () => {
    render(<App />);
    expect(await screen.findByText("Sign in to Kiban")).toBeInTheDocument();
  });

  it("redirects an authenticated visitor from / straight to the app dashboard", async () => {
    fakeSession.isAuthenticated.mockReturnValue(true);
    render(<App />);
    expect(await screen.findByText("Try this")).toBeInTheDocument();
    fakeSession.isAuthenticated.mockReturnValue(false);
  });
});
