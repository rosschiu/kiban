// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { LoginPage } from "../../src/routes/login";

const useShellSession = vi.fn();
vi.mock("../../src/auth/session-context", () => ({ useShellSession: () => useShellSession() }));

describe("LoginPage", () => {
  it("calls session.login() when the Log in button is clicked", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    useShellSession.mockReturnValue({ login });
    const user = userEvent.setup();
    render(<LoginPage />);
    await user.click(screen.getByRole("button", { name: "Log in" }));
    expect(login).toHaveBeenCalledTimes(1);
  });
});
