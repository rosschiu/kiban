// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// After a normal checkout the working tree and `git show HEAD` hold the same committed content,
// so a regression already committed relative to the PARENT commit is invisible to a
// working-tree-vs-HEAD comparison alone. These tests build real git history in a throwaway temp
// repo (git plumbing is exactly what ratchetguard_test.go's own package-level tests deliberately
// avoid, by testing Compare() in isolation — this file is the end-to-end proof those tests
// intentionally leave to cmd/'s own layer) and prove both comparisons independently: a committed
// decrease relative to the parent is caught, and an uncommitted working-tree decrease is caught.

func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=ratchetguard-test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=ratchetguard-test", "GIT_COMMITTER_EMAIL=test@example.invalid",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// newTestRepo creates a throwaway git repo with an initial commit carrying ratchetContent at
// coverage/ratchet.json, returning its root directory.
func newTestRepo(t *testing.T, ratchetContent string) string {
	t.Helper()
	dir := t.TempDir()
	runGitT(t, dir, "init", "-q", "-b", "main")
	writeRatchet(t, dir, ratchetContent)
	runGitT(t, dir, "add", "coverage/ratchet.json")
	runGitT(t, dir, "commit", "-q", "-m", "initial ratchet")
	return dir
}

func writeRatchet(t *testing.T, dir, content string) {
	t.Helper()
	full := filepath.Join(dir, "coverage", "ratchet.json")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write ratchet.json: %v", err)
	}
}

const baselineRatchet = `{"internal/widget": {"min": 80.0, "floor": 80}}`
const loweredRatchet = `{"internal/widget": {"min": 70.0, "floor": 80}}`
const raisedRatchet = `{"internal/widget": {"min": 85.0, "floor": 80}}`

// TestRunAt_CommittedRegressionCaught proves the committed-regression check: a SECOND commit
// that lowers widget's min, with the working tree matching HEAD exactly (a normal post-checkout
// state, where a working-tree-only check passes vacuously), is caught.
func TestRunAt_CommittedRegressionCaught(t *testing.T) {
	dir := newTestRepo(t, baselineRatchet)
	writeRatchet(t, dir, loweredRatchet)
	runGitT(t, dir, "add", "coverage/ratchet.json")
	runGitT(t, dir, "commit", "-q", "-m", "lower widget's min (regression)")

	code := runAt(dir)
	if code != 1 {
		t.Fatalf("runAt() = %d, want 1 (a committed regression relative to the parent commit)", code)
	}
}

// TestRunAt_CommittedIncreaseAllowed is the negative case: a second commit that RAISES the min
// (normal backfill progress) must not be flagged.
func TestRunAt_CommittedIncreaseAllowed(t *testing.T) {
	dir := newTestRepo(t, baselineRatchet)
	writeRatchet(t, dir, raisedRatchet)
	runGitT(t, dir, "add", "coverage/ratchet.json")
	runGitT(t, dir, "commit", "-q", "-m", "raise widget's min (backfill progress)")

	code := runAt(dir)
	if code != 0 {
		t.Fatalf("runAt() = %d, want 0 (a legitimate min increase must not be flagged)", code)
	}
}

// TestRunAt_UncommittedRegressionStillCaught proves the working-tree-vs-HEAD check: an
// uncommitted edit that lowers min, never committed, is caught.
func TestRunAt_UncommittedRegressionStillCaught(t *testing.T) {
	dir := newTestRepo(t, baselineRatchet)
	writeRatchet(t, dir, loweredRatchet) // uncommitted — working tree diverges from HEAD

	code := runAt(dir)
	if code != 1 {
		t.Fatalf("runAt() = %d, want 1 (an uncommitted regression in the working tree)", code)
	}
}

// TestRunAt_NoParentCommit_WarnsAndPassesThatCheck proves the CI-friendliness requirement: a
// repo's very first commit has no parent to compare HEAD against for the committed-regression check, which must
// warn and skip that one comparison — not fail the build — while the working-tree-vs-HEAD check
// still runs normally (and passes here, since nothing changed).
func TestRunAt_NoParentCommit_WarnsAndPassesThatCheck(t *testing.T) {
	dir := newTestRepo(t, baselineRatchet) // exactly one commit — no HEAD^ exists

	code := runAt(dir)
	if code != 0 {
		t.Fatalf("runAt() = %d, want 0 (no parent commit exists yet — must warn and skip that check, not fail)", code)
	}
}

// TestRunAt_CleanRepoPasses is the straightforward positive case: two commits, min only ever
// increases, working tree matches HEAD — both checks pass.
func TestRunAt_CleanRepoPasses(t *testing.T) {
	dir := newTestRepo(t, baselineRatchet)
	writeRatchet(t, dir, raisedRatchet)
	runGitT(t, dir, "add", "coverage/ratchet.json")
	runGitT(t, dir, "commit", "-q", "-m", "raise widget's min")

	code := runAt(dir)
	if code != 0 {
		t.Fatalf("runAt() = %d, want 0", code)
	}
}
