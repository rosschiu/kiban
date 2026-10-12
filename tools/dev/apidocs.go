// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The generated page must load the Redoc renderer exactly this way: Redocly's CDN, pinned
// version, Subresource Integrity hash, anonymous CORS. Anything else means @redocly/cli's
// output shape changed and needs a look. Until 0.1.2 the bundle was inlined for offline
// viewing; that put a vendored minified bundle into the repository, where code scanning
// flagged its internals on every page. The raw spec next to each page stays offline.
var redocCDNScript = regexp.MustCompile(`<script src="https://cdn\.redocly\.com/redoc/v[0-9.]+/bundles/redoc\.standalone\.js" integrity="sha[0-9]+-[^"]+" crossorigin="anonymous"></script>`)

// runAPIDocs is `make docs-api`: one HTML page per modules/*/openapi.yaml plus the platform
// page, through @redocly/cli's build-docs, with the raw YAML copied next to each page for
// client generators, and an index.
func runAPIDocs(args []string) int {
	fs := flag.NewFlagSet("api-docs", flag.ContinueOnError)
	out := fs.String("out", "docs/api", "output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	outDir := abs(*out)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fail("api-docs", err)
	}
	redocly := abs(filepath.Join("web", "node_modules", ".bin", "redocly"))
	if _, err := os.Stat(redocly); err != nil {
		return fail("api-docs", errors.New(redocly+" not found; run `cd web && npm ci` first"))
	}
	type page struct{ name, title, spec string }
	var pages []page
	entries, err := os.ReadDir("modules")
	if err != nil {
		return fail("api-docs", err)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		spec := filepath.Join("modules", e.Name(), "openapi.yaml")
		if _, err := os.Stat(spec); err != nil {
			continue
		}
		pages = append(pages, page{e.Name(), strings.ToUpper(e.Name()[:1]) + e.Name()[1:] + " module API", spec})
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].name < pages[j].name })
	pages = append(pages, page{"platform", "Kiban platform API", filepath.Join("internal", "gateway", "platform-openapi.yaml")})

	for _, p := range pages {
		outFile := filepath.Join(outDir, p.name+".html")
		fmt.Printf("api-docs: %s -> %s\n", p.spec, outFile)
		spec, err := os.ReadFile(p.spec)
		if err != nil {
			return fail("api-docs", err)
		}
		if err := os.WriteFile(filepath.Join(outDir, p.name+".yaml"), spec, 0o644); err != nil {
			return fail("api-docs", err)
		}
		if err := run("", nil, redocly, "build-docs", p.spec, "-o", outFile, "--title", p.title, "--disableGoogleFont"); err != nil {
			return fail("api-docs", fmt.Errorf("redocly build-docs %s: %w", p.spec, err))
		}
		html, err := os.ReadFile(outFile)
		if err != nil {
			return fail("api-docs", err)
		}
		if !redocCDNScript.Match(html) {
			return fail("api-docs", fmt.Errorf("%s does not carry the pinned, integrity-checked Redoc <script> tag; redocly's output shape may have changed, refusing to publish the page", outFile))
		}
	}
	var rows strings.Builder
	for _, p := range pages {
		fmt.Fprintf(&rows, "      <li><a href=\"./%s.html\">%s</a></li>\n", p.name, p.title)
	}
	index := "<!doctype html>\n<html>\n<head>\n  <meta charset=\"utf8\" />\n  <title>Kiban API reference</title>\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n</head>\n<body style=\"font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem;\">\n  <h1>Kiban API reference</h1>\n  <p>Generated from each module's OpenAPI file and the platform OpenAPI file by <code>make docs-api</code>.\n     Each page loads the Redoc renderer from a pinned, integrity-checked CDN script; the raw OpenAPI file sits next to it.</p>\n  <ul>\n" + strings.TrimRight(rows.String(), "\n") + "\n  </ul>\n  <p><a href=\"../\">Back to the documentation</a></p>\n</body>\n</html>\n"
	if err := os.WriteFile(filepath.Join(outDir, "index.html"), []byte(index), 0o644); err != nil {
		return fail("api-docs", err)
	}
	fmt.Printf("api-docs: wrote %s\n", filepath.Join(outDir, "index.html"))
	return 0
}
