// SPDX-License-Identifier: Apache-2.0

// Command ratchetguard fails (exit 1) if any coverage/ratchet.json scope's "min" was lowered or
// any scope was removed — the comparison itself lives in tools/ratchetguard (unit-tested there
// without any git dependency). Wired into `make check` via the Makefile's own ratchet-guard
// target, run alongside (not instead of) coverage-gate.
//
// Comparing the working tree against `git show HEAD` alone is not sufficient: after a normal
// `git checkout`/CI clone the working tree and HEAD are the SAME committed content, so a
// regression that was already committed (a merged PR that lowered a scope's min, a bad rebase,
// ...) would compare HEAD against itself and always pass vacuously. So this runs that
// working-tree-vs-HEAD check (it catches an uncommitted edit before it's even committed), and
// ALSO compares HEAD's own committed content against its parent: the merge-base with
// origin/main when a remote and that branch are reachable (the actual point this branch
// diverged, so a long-lived feature branch's own in-branch history doesn't false-positive
// against unrelated upstream-only movement), falling back to the plain parent (HEAD^) otherwise.
// That second comparison is what actually catches a committed regression.
//
// CI-friendliness (for BOTH comparisons independently): anywhere
// this needs a git ref that doesn't exist — no HEAD at all (a brand-new repo before its first
// commit), no parent commit (HEAD is the repo's first commit), or coverage/ratchet.json didn't
// exist at the ref being compared against — is NOT a violation. ratchetguard prints a loud
// warning and skips that specific comparison (never failing OR silently passing without saying
// why); the other comparison still runs normally.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rosschiu/kiban/tools/ratchetguard"
)

const ratchetPath = "coverage/ratchet.json"

func main() {
	os.Exit(run())
}

func run() int {
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not locate repo root ("+err.Error()+") — skipping both never-decrease checks rather than failing or passing silently")
		return 0
	}
	return runAt(repoRoot)
}

// runAt is run()'s own logic, factored out so tests can point it at a throwaway temp git repo
// instead of this checkout's real one (main_test.go builds real git history — commits with a
// lowered min, an uncommitted working-tree edit, etc. — to prove both comparisons end to end).
func runAt(repoRoot string) int {
	newData, err := os.ReadFile(filepath.Join(repoRoot, ratchetPath))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: ERROR: could not read working-tree "+ratchetPath+": "+err.Error())
		return 1
	}
	workingTree, err := ratchetguard.Parse(newData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: ERROR: "+err.Error())
		return 1
	}

	failed := false

	// Check 1: working tree vs HEAD — catches an UNCOMMITTED regression (mid-edit, before `git
	// add`/commit) before it's ever recorded in history at all.
	if !checkAgainstRef(repoRoot, "HEAD", "HEAD", workingTree) {
		failed = true
	}

	// Check 2: HEAD's own committed content vs its parent — catches a regression that is
	// ALREADY committed, which check 1 alone can never see once the working tree matches HEAD
	// again (every normal checkout/CI clone state).
	if ref, desc, err := parentRef(repoRoot); err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not resolve a parent commit to compare HEAD against ("+err.Error()+") — skipping the committed-regression check rather than failing or passing silently. Expected on a repo's first commit (no parent exists yet); investigate if you see this on an established branch.")
	} else if headData, err := gitShowRef(repoRoot, "HEAD", ratchetPath); err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not read "+ratchetPath+" from HEAD ("+err.Error()+") — skipping the committed-regression check rather than failing or passing silently. Expected on a fresh checkout before any commit.")
	} else if headRatchet, err := ratchetguard.Parse(headData); err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not parse HEAD's "+ratchetPath+" ("+err.Error()+") — skipping the committed-regression check rather than failing or passing silently")
	} else if !checkAgainstRef(repoRoot, ref, desc, headRatchet) {
		failed = true
	}

	if !failed {
		fmt.Println("ratchetguard: OK — no scope's min decreased and no scope was removed, in either the working tree vs HEAD or HEAD vs its parent")
		return 0
	}
	return 1
}

// checkAgainstRef reads coverage/ratchet.json at gitRef, compares it (as the OLDER side) against
// candidate (the NEWER side, already parsed by the caller), and prints any violations. Returns
// false if there were violations OR the ref/path didn't resolve (a loud warning was already
// printed in the latter case — the caller must not treat that as a hard failure by itself, only
// as "this particular comparison did not run"; callers of checkAgainstRef only ever call it after
// already confirming the ref they're passing resolves, so in practice this return value is a
// synonym for "violations found" here).
func checkAgainstRef(repoRoot, gitRef, refDesc string, candidate map[string]ratchetguard.Entry) bool {
	oldData, err := gitShowRef(repoRoot, gitRef, ratchetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not read "+ratchetPath+" from "+refDesc+" ("+err.Error()+") — skipping this check rather than failing or passing silently. Expected on a fresh checkout before any commit, or the ratchet's own first commit; investigate if you see this on an established branch.")
		return true
	}
	oldRatchet, err := ratchetguard.Parse(oldData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ratchetguard: WARNING: could not parse "+refDesc+"'s "+ratchetPath+" ("+err.Error()+") — skipping this check rather than failing or passing silently")
		return true
	}

	violations := ratchetguard.Compare(oldRatchet, candidate)
	if len(violations) == 0 {
		return true
	}
	fmt.Fprintln(os.Stderr, "ratchetguard: coverage/ratchet.json regressed relative to "+refDesc+":")
	for _, v := range violations {
		fmt.Fprintln(os.Stderr, "  - "+v)
	}
	return false
}

// parentRef resolves the ref to compare HEAD's own committed content against for the
// committed-regression check: the merge-base with origin/main when a remote exists, that branch
// is reachable, and the merge-base isn't HEAD itself (i.e. HEAD is genuinely ahead of it — the
// actual divergence point, so this branch's own history since then doesn't trip false positives
// against unrelated upstream-only movement); falls back to the plain parent commit (HEAD^)
// otherwise, including when running directly on main (merge-base(HEAD, origin/main) == HEAD,
// which would make that comparison vacuous the same way a working-tree-only check is). Returns a
// human-readable description of the resolved ref for warning/error messages.
func parentRef(repoRoot string) (ref, desc string, err error) {
	if headSHA, err := runGit(repoRoot, "rev-parse", "HEAD"); err == nil {
		if mb, err := runGit(repoRoot, "merge-base", "HEAD", "origin/main"); err == nil {
			mergeBase := strings.TrimSpace(string(mb))
			if mergeBase != "" && mergeBase != strings.TrimSpace(string(headSHA)) {
				return mergeBase, "merge-base(HEAD, origin/main) " + shortSHA(mergeBase), nil
			}
		}
	}
	if _, err := runGit(repoRoot, "rev-parse", "--verify", "-q", "HEAD^"); err != nil {
		return "", "", fmt.Errorf("no parent commit (HEAD^) exists: %w", err)
	}
	return "HEAD^", "HEAD^ (parent commit)", nil
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func runGit(repoRoot string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot
	return cmd.Output()
}

func gitShowRef(repoRoot, ref, relPath string) ([]byte, error) {
	return runGit(repoRoot, "show", ref+":"+relPath)
}

func findRepoRoot() (string, error) {
	out, err := runGit(".", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
