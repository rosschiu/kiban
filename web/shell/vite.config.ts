// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev loop: Vite dev server proxying /api + /auth to the gateway (no per-module hardcoded proxy
// targets — the shell only ever talks to the one gateway origin). The gateway's dev TLS cert is
// self-signed — secure:false is required for the proxy to reach it locally.
const gatewayOrigin = process.env["VITE_KIBAN_GATEWAY_ORIGIN"] ?? "https://127.0.0.1:8443";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api": { target: gatewayOrigin, changeOrigin: true, secure: false },
      "/auth": { target: gatewayOrigin, changeOrigin: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
  },
});
