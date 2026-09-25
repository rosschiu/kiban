// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ModuleErrorBoundary } from "../../src/ui/error-boundary";

function Boom(): never {
  throw new Error("kaboom");
}

describe("ModuleErrorBoundary", () => {
  it("renders children when there is no error", () => {
    render(
      <ModuleErrorBoundary moduleKey="diagnostics" render={() => <div>fallback</div>}>
        <div>ok content</div>
      </ModuleErrorBoundary>,
    );
    expect(screen.getByText("ok content")).toBeInTheDocument();
  });

  it("catches a render error and renders the fallback with a working retry", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    let shouldThrow = true;

    function Toggle() {
      if (shouldThrow) return <Boom />;
      return <div>recovered</div>;
    }

    const user = userEvent.setup();
    render(
      <ModuleErrorBoundary
        moduleKey="diagnostics"
        render={({ moduleKey, onRetry }) => (
          <button
            onClick={() => {
              shouldThrow = false;
              onRetry();
            }}
          >
            retry {moduleKey}
          </button>
        )}
      >
        <Toggle />
      </ModuleErrorBoundary>,
    );

    expect(screen.getByRole("button", { name: "retry diagnostics" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "retry diagnostics" }));
    expect(screen.getByText("recovered")).toBeInTheDocument();

    consoleSpy.mockRestore();
  });
});
