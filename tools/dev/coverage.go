// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/rosschiu/kiban/tools/coveragegate"
)

// runCoverage is `make coverage-gate` / `make coverage-report`: the Go suite with -tags live
// (needs the isolated test stack, `make test-stack-up`) and both vitest workspaces run with
// coverage instrumentation, then the per-scope evaluation against coverage/ratchet.json.
//
// -count=1 disables Go's test-result cache: several packages hold `-tags live` tests whose
// observed coverage depends on the live stack's current state, which the toolchain cannot
// see; without it an unchanged tree replays a stale profile from a different stack state.
func runCoverage(args []string) int {
	mode := "gate"
	if len(args) > 0 {
		mode = args[0]
	}
	if mode != "gate" && mode != "report" {
		fmt.Fprintln(os.Stderr, "usage: dev coverage [gate|report]")
		return 2
	}
	for _, d := range []string{"coverage", "web/sdk/coverage", "web/shell/coverage"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fail("coverage", err)
		}
	}
	fmt.Println("== coverage: running Go tests with coverage (-tags live; needs the test stack) ==")
	if err := run("", nil, "go", "test", "-p", "1", "-count=1", "-tags", "live",
		"-coverprofile=coverage/go.out", "-coverpkg=./internal/...,./cmd/...,./modules/...,./modulekit/...", "./..."); err != nil {
		return fail("coverage", err)
	}
	for _, ws := range []string{"sdk", "shell"} {
		fmt.Printf("== coverage: running web/%s vitest coverage ==\n", ws)
		if err := run("web", nil, "npm", "run", "-w", ws, "test:coverage"); err != nil {
			return fail("coverage", err)
		}
	}
	fmt.Println("== coverage: evaluating scopes against coverage/ratchet.json ==")
	return coveragegate.Run([]string{"-mode", mode})
}
