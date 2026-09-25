// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { CompanyContextProvider, getCompanySessionContext, useCompanyContext } from "../../src/nav/company-context";

function Probe() {
  const { activeCompanyId, setActiveCompanyId } = useCompanyContext();
  return (
    <div>
      <span data-testid="active">{activeCompanyId ?? "none"}</span>
      <button onClick={() => setActiveCompanyId("company-a")}>set-a</button>
      <button onClick={() => setActiveCompanyId(null)}>clear</button>
    </div>
  );
}

describe("CompanyContextProvider / useCompanyContext", () => {
  // The shared SDK SessionContext is module-level state — clear the active company between tests.
  beforeEach(() => {
    getCompanySessionContext().setActiveCompanyId(null);
  });

  it("throws when used outside the provider", () => {
    expect(() => render(<Probe />)).toThrow(/outside <CompanyContextProvider>/);
  });

  it("starts with no active company", () => {
    render(
      <CompanyContextProvider>
        <Probe />
      </CompanyContextProvider>,
    );
    expect(screen.getByTestId("active")).toHaveTextContent("none");
  });

  it("re-renders with the new active company after setActiveCompanyId", async () => {
    const user = userEvent.setup();
    render(
      <CompanyContextProvider>
        <Probe />
      </CompanyContextProvider>,
    );
    await user.click(screen.getByRole("button", { name: "set-a" }));
    expect(screen.getByTestId("active")).toHaveTextContent("company-a");
    await user.click(screen.getByRole("button", { name: "clear" }));
    expect(screen.getByTestId("active")).toHaveTextContent("none");
  });
});
