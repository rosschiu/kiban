#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// `make docs-api` — bundles every module's openapi.yaml plus the
// platform-openapi.yaml fragment into HTML under docs/api/, one page per module + the platform
// page, using @redocly/cli's `build-docs` (the actively-maintained successor to the abandoned
// redoc-cli).
//
// The generated page loads the Redoc renderer from Redocly's CDN through ONE <script> tag that
// pins the exact version and carries a Subresource Integrity hash, so the browser refuses any
// other bytes. Until 0.1.2 this script inlined the same bundle verbatim for offline viewing;
// that put a vendored minified bundle into the repository, where code scanning flagged its
// internals on every page. The spec itself (the raw YAML next to each page) stays offline.
//
// Usage: node scripts/build-api-docs.mjs [--out <dir>]   (default --out docs/api)
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
}

const outDir = resolve(repoRoot, arg("--out", "docs/api"));
mkdirSync(outDir, { recursive: true });

// The page must reference the renderer exactly this way: pinned version, integrity hash,
// anonymous CORS. Anything else means redocly's output shape changed and needs a look.
const cdnScriptRe = /<script src="https:\/\/cdn\.redocly\.com\/redoc\/v[0-9.]+\/bundles\/redoc\.standalone\.js" integrity="sha[0-9]+-[^"]+" crossorigin="anonymous"><\/script>/;

// pages: [{ name, title, specPath }] — one per module's openapi.yaml, plus the platform surface.
const modulesDir = join(repoRoot, "modules");
const pages = readdirSync(modulesDir, { withFileTypes: true })
  .filter((e) => e.isDirectory() && !e.name.startsWith("_"))
  .map((e) => ({
    name: e.name,
    title: `${e.name[0].toUpperCase()}${e.name.slice(1)} module API`,
    specPath: join(modulesDir, e.name, "openapi.yaml")
  }))
  .filter((p) => existsSync(p.specPath))
  .sort((a, b) => a.name.localeCompare(b.name));

pages.push({
  name: "platform",
  title: "Kiban platform API",
  specPath: join(repoRoot, "internal", "gateway", "platform-openapi.yaml")
});

const redoclyBin = join(repoRoot, "web", "node_modules", ".bin", "redocly");

for (const page of pages) {
  const outFile = join(outDir, `${page.name}.html`);
  console.log(`build-api-docs: ${page.specPath} -> ${outFile}`);
  // The raw file next to the rendered page, for client generators (openapi-generator, orval...).
  copyFileSync(page.specPath, join(outDir, `${page.name}.yaml`));
  execFileSync(redoclyBin, ["build-docs", page.specPath, "-o", outFile, "--title", page.title, "--disableGoogleFont"], {
    cwd: repoRoot,
    stdio: "inherit"
  });

  const html = readFileSync(outFile, "utf8");
  if (!cdnScriptRe.test(html)) {
    console.error(`build-api-docs: ${outFile} does not carry the pinned, integrity-checked Redoc <script> tag — redocly's output shape may have changed; refusing to publish the page.`);
    process.exit(1);
  }
}

const indexPath = join(outDir, "index.html");
const rows = pages
  .map((p) => `      <li><a href="./${p.name}.html">${p.title}</a></li>`)
  .join("\n");
writeFileSync(
  indexPath,
  `<!doctype html>
<html>
<head>
  <meta charset="utf8" />
  <title>Kiban API reference</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem;">
  <h1>Kiban API reference</h1>
  <p>Generated from each module's OpenAPI file and the platform OpenAPI file by <code>make docs-api</code>.
     Each page is a self-contained, offline-viewable bundle — no CDN required.</p>
  <ul>
${rows}
  </ul>
  <p><a href="../">Back to the documentation</a></p>
</body>
</html>
`
);
console.log(`build-api-docs: wrote ${indexPath}`);
