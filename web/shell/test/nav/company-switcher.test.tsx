// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { CompanySwitcher } from "../../src/nav/company-switcher";

describe("CompanySwitcher", () => {
  it("renders nothing when there are no companies", () => {
    const { container } = render(<CompanySwitcher companies={[]} activeCompanyId={null} onSwitch={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists every company as an option and selects the active one", () => {
    render(
      <CompanySwitcher
        companies={[
          { id: "company-a", code: "A", name: "Company A", isActive: true },
          { id: "company-b", code: "B", name: "Company B", isActive: true },
        ]}
        activeCompanyId="company-b"
        onSwitch={vi.fn()}
      />,
    );
    const select = screen.getByTestId("company-switcher-select") as HTMLSelectElement;
    expect(select.value).toBe("company-b");
    expect(screen.getByRole("option", { name: "Company A" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Company B" })).toBeInTheDocument();
  });

  it("calls onSwitch with the newly selected company id", async () => {
    const onSwitch = vi.fn();
    const user = userEvent.setup();
    render(
      <CompanySwitcher
        companies={[
          { id: "company-a", code: "A", name: "Company A", isActive: true },
          { id: "company-b", code: "B", name: "Company B", isActive: true },
        ]}
        activeCompanyId="company-a"
        onSwitch={onSwitch}
      />,
    );
    await user.selectOptions(screen.getByTestId("company-switcher-select"), "company-b");
    expect(onSwitch).toHaveBeenCalledWith("company-b");
  });
});
