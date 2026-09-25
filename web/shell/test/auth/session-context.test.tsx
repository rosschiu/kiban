// SPDX-License-Identifier: Apache-2.0

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const fakeSession = {
  login: vi.fn().mockResolvedValue(undefined),
  buildLoginUrl: vi.fn(),
  handleCallback: vi.fn().mockResolvedValue({ accessToken: "tok", expiresAt: Date.now() + 60_000 }),
  getAccessToken: vi.fn().mockReturnValue(null as string | null),
  refresh: vi.fn(),
  logout: vi.fn(),
  getTokens: vi.fn(),
  isAuthenticated: vi.fn().mockReturnValue(false),
};
const fakeApiClient = { baseUrl: "https://gateway.invalid", request: vi.fn() };

// Captures the listener session-context.tsx registers so tests can simulate a
// mid-journey silent-refresh failure without going through a real apiClient/fetch cycle.
let invalidationListener: (() => void) | undefined;
vi.mock("../../src/auth/sdk", () => ({
  getShellSdk: () => ({ session: fakeSession, apiClient: fakeApiClient }),
  onShellSessionInvalidated: (listener: () => void) => {
    invalidationListener = listener;
    return () => {
      invalidationListener = undefined;
    };
  },
}));

const fakeCompanySessionContext = { clear: vi.fn() };
vi.mock("../../src/nav/company-context", () => ({
  getCompanySessionContext: () => fakeCompanySessionContext,
}));

// Imported after the mocks so the module under test picks up the mocked "./sdk" and
// "../nav/company-context".
const { ShellSessionProvider, useShellSession } = await import("../../src/auth/session-context");

function Probe() {
  const { isAuthenticated, login, logout, handleCallback } = useShellSession();
  return (
    <div>
      <span data-testid="status">{isAuthenticated ? "in" : "out"}</span>
      <button onClick={() => void login()}>login</button>
      <button onClick={() => void handleCallback("https://app.invalid/callback?code=c&state=s")}>callback</button>
      <button onClick={logout}>logout</button>
    </div>
  );
}

describe("ShellSessionProvider / useShellSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fakeSession.isAuthenticated.mockReturnValue(false);
    fakeSession.getAccessToken.mockReturnValue(null);
  });

  it("throws when used outside the provider", () => {
    // Swallow the expected React error-boundary console output for this one assertion.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Probe />)).toThrow(/outside <ShellSessionProvider>/);
    spy.mockRestore();
  });

  it("reflects isAuthenticated:false before login and calls session.login() on demand", async () => {
    const user = userEvent.setup();
    render(
      <ShellSessionProvider>
        <Probe />
      </ShellSessionProvider>,
    );

    expect(screen.getByTestId("status")).toHaveTextContent("out");
    await user.click(screen.getByRole("button", { name: "login" }));
    expect(fakeSession.login).toHaveBeenCalledTimes(1);
  });

  it("re-renders with isAuthenticated:true after a successful handleCallback", async () => {
    const user = userEvent.setup();
    render(
      <ShellSessionProvider>
        <Probe />
      </ShellSessionProvider>,
    );

    fakeSession.isAuthenticated.mockReturnValue(false);
    await user.click(screen.getByRole("button", { name: "callback" }));
    expect(fakeSession.handleCallback).toHaveBeenCalledWith("https://app.invalid/callback?code=c&state=s");

    fakeSession.isAuthenticated.mockReturnValue(true);
    fakeSession.getAccessToken.mockReturnValue("tok");
    // Re-invoke the same state-changing call: it bumps the provider's version counter again,
    // forcing it to re-read the (now authenticated) session getters — mirroring how a real
    // second callback/refresh cycle would surface an updated auth state.
    await user.click(screen.getByRole("button", { name: "callback" }));
    expect(screen.getByTestId("status")).toHaveTextContent("in");
  });

  it("calls session.logout() and bumps state on logout", async () => {
    const user = userEvent.setup();
    render(
      <ShellSessionProvider>
        <Probe />
      </ShellSessionProvider>,
    );
    await user.click(screen.getByRole("button", { name: "logout" }));
    expect(fakeSession.logout).toHaveBeenCalledTimes(1);
  });

  it("logout() also clears the app-side SessionContext (active company, preferences), not just tokens", async () => {
    const user = userEvent.setup();
    render(
      <ShellSessionProvider>
        <Probe />
      </ShellSessionProvider>,
    );
    await user.click(screen.getByRole("button", { name: "logout" }));
    expect(fakeCompanySessionContext.clear).toHaveBeenCalledTimes(1);
  });

  it("a mid-journey session invalidation (revoked-refresh-token failure, notified via onShellSessionInvalidated) re-renders isAuthenticated:false without an explicit logout() call", async () => {
    fakeSession.isAuthenticated.mockReturnValue(true);
    fakeSession.getAccessToken.mockReturnValue("tok");
    render(
      <ShellSessionProvider>
        <Probe />
      </ShellSessionProvider>,
    );
    expect(screen.getByTestId("status")).toHaveTextContent("in");

    // Simulate what sdk.ts's `refreshAccessToken` wrapper does after a conclusively-failed
    // silent refresh: the session is now cleared, and the listener session-context.tsx
    // registered on mount fires.
    fakeSession.isAuthenticated.mockReturnValue(false);
    fakeSession.getAccessToken.mockReturnValue(null);
    expect(invalidationListener).toBeDefined();
    act(() => invalidationListener!());

    expect(screen.getByTestId("status")).toHaveTextContent("out");
    // Never went through logout() itself — this is the failure-path notification, not a user
    // action — so neither of logout()'s own side effects fired.
    expect(fakeSession.logout).not.toHaveBeenCalled();
    expect(fakeCompanySessionContext.clear).not.toHaveBeenCalled();
  });
});
