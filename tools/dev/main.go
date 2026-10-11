// SPDX-License-Identifier: Apache-2.0

// Command dev is the one developer tool behind the Makefile: every gate and generator that is
// not a Go service lives here as a subcommand, so `make <target>` is one line and nothing is
// CI-only (ci.yml and release.yml call the same targets a human runs).
//
//	go run ./tools/dev <subcommand> [args]
//
// Subcommands: coverage, license-check, license-scan, ratchet-guard, modvalidate, k8s-check,
// pin-images, quickstart-compose, api-docs. Each prints its own usage on -h.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rosschiu/kiban/tools/coveragegate"
	"github.com/rosschiu/kiban/tools/licensecheck"
	"github.com/rosschiu/kiban/tools/ratchetguard"
)

var subcommands = map[string]struct {
	help string
	run  func(args []string) int
}{
	"coverage":           {"run the Go and web test suites with coverage and evaluate coverage/ratchet.json (gate|report)", runCoverage},
	"coverage-eval":      {"evaluate existing coverage profiles against coverage/ratchet.json", coveragegate.Run},
	"license-check":      {"every source file carries its SPDX header (-fix inserts them)", licensecheck.Run},
	"license-scan":       {"third-party licence scan of Go and npm dependencies; regenerates THIRD-PARTY-LICENSES.md", runLicenseScan},
	"ratchet-guard":      {"coverage/ratchet.json never decreases, working tree vs HEAD and HEAD vs parent", func([]string) int { return ratchetguard.Run() }},
	"modvalidate":        {"validate module directories or migration trees; -write-checksums records a ledger", runModvalidate},
	"k8s-check":          {"render the Kustomize base and overlays without a cluster and check the Secret rules", runK8sCheck},
	"pin-images":         {"rewrite every third-party image reference to its current digest", runPinImages},
	"quickstart-compose": {"generate the zero-clone quickstart compose file from infra/compose.yaml (--public for the overlay)", runQuickstartCompose},
	"api-docs":           {"bundle every OpenAPI file into HTML under --out (default docs/api)", runAPIDocs},
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		usage()
		os.Exit(2)
	}
	sub, ok := subcommands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "dev: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err := os.Chdir(repoRoot()); err != nil {
		fmt.Fprintln(os.Stderr, "dev:", err)
		os.Exit(2)
	}
	os.Exit(sub.run(os.Args[2:]))
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: go run ./tools/dev <subcommand> [args]")
	names := make([]string, 0, len(subcommands))
	for n := range subcommands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-20s %s\n", n, subcommands[n].help)
	}
}

// repoRoot is the git toplevel, so every subcommand runs from the repository root whatever
// directory it was invoked from.
func repoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	return strings.TrimSpace(string(out))
}

// run executes a command with inherited stdio in dir ("" = current), returning its error.
func run(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.Run()
}

// output executes a command and returns its stdout; stderr is captured into the error.
func output(dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func fail(sub string, err error) int {
	fmt.Fprintf(os.Stderr, "%s: FAIL: %v\n", sub, err)
	return 1
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
