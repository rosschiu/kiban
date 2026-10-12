// SPDX-License-Identifier: Apache-2.0

// Command licensecheck is `make license-check`'s SPDX header verifier: walks the repo
// from the current working directory (expected to be the repo root — the Makefile invokes it
// that way), checks every first-party Go/TS/TSX/SQL/shell file against tools/licensecheck's zone
// rules, and fails loudly (exit 1) listing every file missing its header. `-fix` applies the
// missing headers instead of failing (for a contributor who adds a new first-party file without
// its header).
package licensecheck

import (
	"flag"
	"fmt"
	"os"
)

// Run is the `license-check` subcommand: every source file carries its SPDX header.
func Run(args []string) int {
	fs := flag.NewFlagSet("license-check", flag.ContinueOnError)
	fix := fs.Bool("fix", false, "insert missing SPDX headers instead of failing")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	findings, err := Walk(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "license-check: ERROR walking repo:", err)
		return 1
	}

	var missing []Finding
	okCount, genCount := 0, 0
	for _, f := range findings {
		switch f.Status {
		case "ok":
			okCount++
		case "generated-skip":
			genCount++
		case "missing":
			missing = append(missing, f)
		}
	}

	if *fix {
		n, err := Fix(".", missing)
		if err != nil {
			fmt.Fprintln(os.Stderr, "license-check -fix: ERROR:", err)
			return 1
		}
		fmt.Printf("license-check -fix: inserted headers into %d file(s)\n", n)
		return 0
	}

	if len(missing) == 0 {
		fmt.Printf("license-check: PASS (%d file(s) OK, %d generated-skip)\n", okCount, genCount)
		return 0
	}

	fmt.Fprintf(os.Stderr, "license-check: FAIL — %d file(s) missing their SPDX header:\n", len(missing))
	for _, f := range missing {
		fmt.Fprintf(os.Stderr, "  %s (want %q)\n", f.Path, f.Want)
	}
	fmt.Fprintln(os.Stderr, "Run `go run ./tools/dev license-check -fix` to insert them.")
	return 1
}
