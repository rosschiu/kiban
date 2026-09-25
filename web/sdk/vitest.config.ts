// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
    restoreMocks: true,
    coverage: {
      // Restricted to web/sdk/src behavior code only — e2e/, docs-snippets/, and
      // playwright-report/ are not gated (the default v8 sweep would distort the numbers).
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts"],
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage"
    }
  }
});
