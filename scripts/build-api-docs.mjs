#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// `make docs-api` — bundles every module's openapi.yaml plus the
// platform-openapi.yaml fragment into standalone HTML under docs/api/, one page per module + the
// platform page, using @redocly/cli's `build-docs` (the actively-maintained successor to the
// abandoned redoc-cli) as a single-file
// renderer with NO external CDN reference at view time.
//
// @redocly/cli's default output embeds a <script src="https://cdn.redocly.com/..."> reference to
// load the Redoc renderer (confirmed by inspecting its generated output) — there is no CLI flag
// to inline it. This script post-processes that one <script> tag, replacing it with the SAME
// redoc version's own bundles/redoc.standalone.js content inlined verbatim (the `redoc` npm
// package, pinned to the exact version @redocly/cli's own build-docs targets, installed as a
// devDependency for exactly this purpose — see web/package.json). Everything else in the
// generated page (styles, the pre-rendered spec data) is already inline; this is the only
// network-at-view-time reference to strip.
//
// Usage: node scripts/build-api-docs.mjs [--out <dir>]   (default --out docs/api)
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
}

const outDir = resolve(repoRoot, arg("--out", "docs/api"));
mkdirSync(outDir, { recursive: true });

const redocBundlePath = join(repoRoot, "web", "node_modules", "redoc", "bundles", "redoc.standalone.js");
if (!existsSync(redocBundlePath)) {
  console.error(
    `build-api-docs: ${redocBundlePath} not found — run \`npm --prefix web install\` first (redoc is a devDependency of web/, installed alongside @redocly/cli specifically to provide this offline bundle).`
  );
  process.exit(1);
}
// Escape any literal "</script>" inside the bundle's own source (it contains string constants
// that embed one, e.g. its own HTML-escaping helpers) — inlined raw, that substring would
// terminate this file's actual <script> tag early and let the browser's HTML parser start
// re-interpreting the REST of the bundle's JS text as literal markup, resurrecting exactly the
// external <script src="https://cdn..."> tag this whole post-processing step exists to remove
// (confirmed empirically: an HTMLParser pass over the naive inlining found MULTIPLE real
// <script src="cdn.redocly.com/..."> elements, not just inert text, for exactly this reason).
const redocBundleJS = readFileSync(redocBundlePath, "utf8").replace(/<\/script/gi, "<\\/script");
const cdnScriptRe = /<script src="https:\/\/cdn\.redocly\.com\/redoc\/[^"]*" integrity="[^"]*" crossorigin="anonymous"><\/script>/;

// Generated pages reference "redoc.standalone.js.LICENSE.txt" in their own header comment (see
// the `/*! For license information please see redoc.standalone.js.LICENSE.txt */` banner every
// bundled minified chunk carries), so that file must be copied into the output directory — it is
// the attribution notice a bundled third-party dependency legally requires.
// Copy it in verbatim (never regenerate/rewrite it — it's redoc's own file, not ours).
const redocLicenseNoticePath = join(repoRoot, "web", "node_modules", "redoc", "bundles", "redoc.standalone.js.LICENSE.txt");
if (!existsSync(redocLicenseNoticePath)) {
  console.error(
    `build-api-docs: ${redocLicenseNoticePath} not found — run \`npm --prefix web install\` first (same redoc devDependency the bundle inline above needs).`
  );
  process.exit(1);
}
writeFileSync(join(outDir, "redoc.standalone.js.LICENSE.txt"), readFileSync(redocLicenseNoticePath));

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
  execFileSync(redoclyBin, ["build-docs", page.specPath, "-o", outFile, "--title", page.title, "--disableGoogleFont"], {
    cwd: repoRoot,
    stdio: "inherit"
  });

  let html = readFileSync(outFile, "utf8");
  if (!cdnScriptRe.test(html)) {
    console.error(`build-api-docs: ${outFile} does not contain the expected CDN <script> tag — redocly's output shape may have changed; refusing to publish a page that might still reference a CDN.`);
    process.exit(1);
  }
  // A FUNCTION replacer, never a string one: redoc.standalone.js's own minified source contains
  // literal "$&"/"$1"-shaped substrings (ordinary regex-replace calls within its own code) that
  // String.replace's STRING-replacement form would reinterpret as special patterns — confirmed
  // empirically: a string-replacement version of this line reinserted the matched CDN <script>
  // tag verbatim at every "$&" occurrence inside the bundle, silently resurrecting the exact CDN
  // reference this post-processing step exists to remove. A function replacer's return value is
  // used verbatim, with no such reinterpretation.
  html = html.replace(cdnScriptRe, () => `<script>\n${redocBundleJS}\n</script>`);
  writeFileSync(outFile, html);
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
