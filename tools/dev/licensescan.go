// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Pinned tool versions, never @latest, for reproducibility.
const (
	goLicensesVersion     = "v2.0.1"
	licenseCheckerVersion = "25.0.1"
)

var (
	// Word-boundary match on the licence id itself (never a bare substring of "GPL", which
	// would also hit "MPL"): GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0 and their -or-later/-only
	// SPDX suffix variants.
	forbiddenLicense = regexp.MustCompile(`(^|[^A-Za-z])(A?GPL)(-[0-9]+(\.[0-9]+)*)?([^A-Za-z]|$)|SSPL`)
	// An unclassified licence is not proof of compatibility, it is proof the scan could not
	// tell. "Unlicense" (a real public-domain dedication) is deliberately not matched.
	unknownLicense = regexp.MustCompile(`(^|[^A-Za-z0-9])(UNKNOWN|UNLICENSED|unclassified)([^A-Za-z0-9]|$)`)
)

// runLicenseScan is `make license-scan`: go-licenses over the Go module and license-checker
// over the web/ workspace, failing on any copyleft-incompatible or unclassified licence, and on
// success regenerating THIRD-PARTY-LICENSES.md so the inventory never drifts from the
// dependency set. This scan is about dependencies; our own files are `license-check`.
func runLicenseScan(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: dev license-scan")
		return 2
	}
	fmt.Fprintf(os.Stderr, "license-scan: running go-licenses (pinned %s)...\n", goLicensesVersion)
	// --template '' selects the CSV report (module,url,license). A tool failure is a scan
	// failure, never an empty inventory that passes.
	csv, err := output("", "go", "run", "github.com/google/go-licenses/v2@"+goLicensesVersion, "report", "./...", "--template", "")
	if err != nil {
		return fail("license-scan", fmt.Errorf("go-licenses report failed: %w", err))
	}
	type goDep struct{ module, url, license string }
	var goDeps []goDep
	for _, line := range strings.Split(strings.TrimSpace(string(csv)), "\n") {
		if line == "" || strings.HasPrefix(line, "github.com/rosschiu/kiban") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			return fail("license-scan", fmt.Errorf("unexpected go-licenses line: %q", line))
		}
		goDeps = append(goDeps, goDep{parts[0], parts[1], parts[2]})
	}
	if len(goDeps) == 0 {
		return fail("license-scan", errors.New("go-licenses produced an empty Go dependency inventory"))
	}

	fmt.Fprintf(os.Stderr, "license-scan: running npm license-checker (pinned %s) over web/...\n", licenseCheckerVersion)
	raw, err := output("web", "npx", "--yes", "license-checker@"+licenseCheckerVersion, "--json", "--excludePrivatePackages")
	if err != nil {
		return fail("license-scan", fmt.Errorf("npm license-checker failed: %w", err))
	}
	var npm map[string]struct {
		Licenses any `json:"licenses"`
	}
	if err := json.Unmarshal(raw, &npm); err != nil {
		return fail("license-scan", fmt.Errorf("parse license-checker output: %w", err))
	}
	if len(npm) == 0 {
		return fail("license-scan", errors.New("npm license-checker produced an empty npm dependency inventory"))
	}
	npmLicense := func(pkg string) string {
		switch v := npm[pkg].Licenses.(type) {
		case nil:
			return ""
		case string:
			return v
		default:
			b, _ := json.Marshal(v)
			return string(b)
		}
	}

	fmt.Fprintln(os.Stderr, "license-scan: checking for copyleft-incompatible and unknown/unclassified licenses...")
	var goViolations, goUnknown, npmViolations, npmUnknown []string
	// The licence column decides, never the URL: go-licenses answers "Unknown" there for a module
	// it cannot map to a repository (gopkg.in/yaml.v3) while still classifying its licence.
	for _, d := range goDeps {
		row := d.module + "," + d.url + "," + d.license
		if forbiddenLicense.MatchString(d.license) {
			goViolations = append(goViolations, row)
		}
		if unknownLicense.MatchString(d.license) {
			goUnknown = append(goUnknown, row)
		}
	}
	npmNames := make([]string, 0, len(npm))
	for pkg := range npm {
		npmNames = append(npmNames, pkg)
	}
	sort.Strings(npmNames)
	for _, pkg := range npmNames {
		lic := npmLicense(pkg)
		if forbiddenLicense.MatchString(lic) {
			npmViolations = append(npmViolations, pkg+": "+lic)
		}
		if strings.TrimSpace(lic) == "" || unknownLicense.MatchString(lic) {
			if lic == "" {
				lic = "(empty)"
			}
			npmUnknown = append(npmUnknown, pkg+": "+lic)
		}
	}
	if len(goViolations)+len(goUnknown)+len(npmViolations)+len(npmUnknown) > 0 {
		fmt.Fprintln(os.Stderr, "license-scan: FAIL — a distributed component carries a forbidden, unknown, or unclassified license:")
		report := func(title string, rows []string) {
			if len(rows) == 0 {
				return
			}
			fmt.Fprintln(os.Stderr, "  "+title+":")
			for _, r := range rows {
				fmt.Fprintln(os.Stderr, "    "+r)
			}
		}
		report("Go (copyleft-incompatible)", goViolations)
		report("Go (unknown/unclassified)", goUnknown)
		report("npm (copyleft-incompatible)", npmViolations)
		report("npm (unknown/unclassified)", npmUnknown)
		return 1
	}
	fmt.Fprintln(os.Stderr, "license-scan: PASS — no GPL/AGPL/SSPL-family or unknown/unclassified license found in any Go or npm dependency")

	// The inventory, regenerated so it cannot drift from what was scanned.
	var b strings.Builder
	fmt.Fprintf(&b, "# Third-Party License Inventory\n\nGenerated by `make license-scan` (`go run ./tools/dev license-scan`); regenerate after any\ndependency change, never hand-edit.\n\n")
	fmt.Fprintf(&b, "Scanned %s with go-licenses `%s` and npm\nlicense-checker `%s`. Gate: `make license-scan` fails this build if\nany entry below is later found to carry a GPL/AGPL/SSPL-family license — none do as of\nthis scan.\n\n", time.Now().UTC().Format("2006-01-02"), goLicensesVersion, licenseCheckerVersion)
	fmt.Fprintf(&b, "## Go dependencies (%d entries)\n\n| Module | License | Source |\n|---|---|---|\n", len(goDeps))
	goRows := make([]string, 0, len(goDeps))
	for _, d := range goDeps {
		goRows = append(goRows, fmt.Sprintf("| `%s` | %s | %s |", d.module, d.license, d.url))
	}
	sort.Strings(goRows)
	for _, r := range goRows {
		b.WriteString(r + "\n")
	}
	fmt.Fprintf(&b, "\n## npm dependencies (web/ workspace, %d entries)\n\n| Package | License |\n|---|---|\n", len(npm))
	for _, pkg := range npmNames {
		lic := npmLicense(pkg)
		if lic == "" {
			lic = "?"
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", pkg, lic)
	}
	if err := os.WriteFile("THIRD-PARTY-LICENSES.md", []byte(b.String()), 0o644); err != nil {
		return fail("license-scan", err)
	}
	fmt.Fprintln(os.Stderr, "license-scan: wrote THIRD-PARTY-LICENSES.md")
	return 0
}
