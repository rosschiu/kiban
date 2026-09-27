// Zero-dependency static file server for the e2e harness (native node:http/node:fs only —
// the package takes no new runtime deps; this is dev/test tooling, not published package code, but
// keeping it dependency-free avoids yet another devDependency for something this small).
// Serves two roots on one origin: `/sdk/*` -> `../dist` (the built @kiban/sdk ESM bundle, so the
// harness pages can `import` it exactly like a real consumer would) and everything else ->
// `./harness` (the e2e login/callback pages).
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(here, "..", "dist");
const harnessDir = path.join(here, "harness");
const port = Number(process.env.PORT ?? 5173);

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function contentType(filePath) {
  return contentTypes[path.extname(filePath)] ?? "application/octet-stream";
}

// harness/config.js hardcodes the gateway origin as a readable default, but the real
// value must track whichever stack this run actually targets (playwright.config.ts resolves
// KIBAN_GATEWAY_TLS_HOST_PORT from .env.test and passes it here via webServer.env — the
// isolated kiban-test stack's gateway TLS port, never .env's live/public one). Textual
// substitution of the one hardcoded origin string keeps harness/config.js as the single
// readable source of the rest of the fixture config.
async function serveConfigJs(res) {
  const raw = await readFile(path.join(harnessDir, "config.js"), "utf8");
  const gatewayPort = process.env.KIBAN_GATEWAY_TLS_HOST_PORT ?? "8443";
  const body = raw.replace("https://127.0.0.1:8443", `https://127.0.0.1:${gatewayPort}`);
  res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" }).end(body);
}

async function serveFile(res, root, relativePath) {
  const resolved = path.normalize(path.join(root, relativePath));
  if (!resolved.startsWith(root)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  try {
    const body = await readFile(resolved);
    res.writeHead(200, { "content-type": contentType(resolved) }).end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname.startsWith("/sdk/")) {
    void serveFile(res, distDir, url.pathname.slice("/sdk/".length));
    return;
  }
  const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  if (relative === "config.js") {
    void serveConfigJs(res);
    return;
  }
  void serveFile(res, harnessDir, relative);
});

server.listen(port, "127.0.0.1", () => {
  // eslint-disable-next-line no-console
  console.log(`[e2e harness] listening on http://127.0.0.1:${port}`);
});
