// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv } from "../../e2e-shared/env.js";

// Playwright e2e against the ISOLATED `kiban-test` stack (`make test-stack-up`,
// .env.test — never .env's live/public stack). `npm run -w sdk e2e` (package.json's
// `pree2e` runs `npm run build` first, so the harness always imports the freshly built
// dist/index.js). Requires the isolated stack up first — globalSetup fails loudly (not
// silently) if it isn't. The harness's gatewayOrigin (served as /config.js by
// static-server.mjs) is derived from the same KIBAN_GATEWAY_TLS_HOST_PORT, passed through here
// via webServer.env since Playwright starts webServer before globalSetup runs.
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
  webServer: {
    command: "node ./static-server.mjs",
    cwd: import.meta.dirname,
    port: 5173,
    env: { KIBAN_GATEWAY_TLS_HOST_PORT: gatewayTlsPort },
    reuseExistingServer: false,
    timeout: 10_000
  },
  use: {
    ignoreHTTPSErrors: true,
    baseURL: "http://localhost:5173",
    // Suite default: keep a video only when something goes wrong. e2e/login.spec.ts overrides
    // this to "on" via test.use() so the full flow always has a recording.
    video: "retain-on-failure",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  }
});
