// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv } from "../../e2e-shared/env.js";

// Playwright e2e against the ISOLATED `kiban-test` stack (`make test-stack-up`,
// .env.test), served BY that stack's own gateway (self-signed TLS on
// KIBAN_GATEWAY_TLS_HOST_PORT — KIBAN_STATIC_DIR points at web/shell's built dist,
// infra/compose.yaml). Unlike web/sdk's own e2e harness (a standalone static server on
// localhost:5173), there is no `webServer` here: the shell IS the thing the stack already
// serves, so this suite only needs the isolated stack up first (`make test-stack-up`), same
// requirement as infra/e2e-login.sh had for `make dev`. `npm run -w shell e2e`'s `pree2e` script
// builds the shell so a local dev loop matches what's actually running in the container, but the
// container's own bundle (baked in at image-build time) is what a real run against the isolated
// stack exercises. baseURL is resolved from .env.test (KIBAN_GATEWAY_TLS_HOST_PORT) here,
// at config-eval time — loadTestEnv() throws its refusal message immediately (before any test or
// globalSetup runs) if .env.test is absent or the live-stack signal trips.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const testEnv = loadTestEnv(repoRoot);
const gatewayTlsPort = testEnv.KIBAN_GATEWAY_TLS_HOST_PORT ?? "8443";

export default defineConfig({
  testDir: ".",
  outputDir: "../e2e-artifacts",
  timeout: 60_000,
  retries: 0,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"], ["html", { open: "never", outputFolder: "../playwright-report" }]],
  globalSetup: "./global-setup.ts",
  use: {
    baseURL: `https://127.0.0.1:${gatewayTlsPort}`,
    ignoreHTTPSErrors: true,
    // Video always-on, retained (not just on-failure) under web/shell/e2e-artifacts/.
    video: "on",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  }
});
