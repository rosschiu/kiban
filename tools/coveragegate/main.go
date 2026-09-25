// SPDX-License-Identifier: Apache-2.0

// Command coveragegate implements the coverage ratchet: it parses Go and web coverage
// profiles, aggregates them into the scopes listed in `scopes` below, and compares each scope's
// current statement coverage against coverage/ratchet.json.
//
// Ratchet rule: coverage/ratchet.json holds a per-scope "min" — the floor currently enforced by
// `make check` — and a "floor" — the target (95% security-critical, 80% general). "min" is
// RAISED toward "floor" as tests are added; a scope is "done" when min == floor. Minimums may
// only ever increase, never decrease — enforced by tools/ratchetguard (`make ratchet-guard`),
// not by this tool, to keep the gate itself simple and dependency-free.
//
// Two modes:
//   - "gate":   exit 1 if any scope's current coverage is below its ratchet min (used by
//     `make check`'s coverage-gate target).
//   - "report": always exits 0; prints the same table plus a gap-to-floor column (used by
//     `make coverage-report`).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

// scopeDef describes how to compute one scope's statement coverage from the two raw coverage
// sources. Go scopes match a package directory (relative to the module root) plus an optional
// file allow/deny list. Web scopes match a relative path prefix under web/sdk/src.
type scopeDef struct {
	name  string
	floor float64

	// Go scope fields. goPkgDir is the package directory relative to the module root, e.g.
	// "internal/gateway". Files directly in that directory (not subdirectories) are candidates.
	goPkgDir     string
	goOnlyFiles  map[string]bool // non-nil: only these basenames count (a security-critical subset)
	goExceptFile map[string]bool // non-nil: all files in goPkgDir except these count ("rest of package")

	// Web scope fields. webSource selects which web coverage source this scope reads from ("sdk"
	// — the default/zero value, or "shell"); webPrefix is the path prefix (relative to that
	// source's own src/ dir) a file must have to belong to this scope. webExceptPrefix, if set,
	// excludes files with that prefix instead. A scope with neither prefix set (e.g. "web/shell"
	// itself) matches every file from its source.
	webSource       string
	webPrefix       string
	webExceptPrefix string
}

const webSourceShell = "shell"

// scopes lists every gated scope: the security-critical scopes (95% floor) first, then the
// general scopes (80% floor), then web/shell.
var scopes = []scopeDef{
	{name: "internal/authz/engine", floor: 95, goPkgDir: "internal/authz/engine"},
	{name: "internal/authz/decision", floor: 95, goPkgDir: "internal/authz/decision"},
	{name: "internal/identity", floor: 95, goPkgDir: "internal/identity"},
	{name: "internal/audit", floor: 95, goPkgDir: "internal/audit"},
	{name: "internal/gateway.critical", floor: 95, goPkgDir: "internal/gateway",
		goOnlyFiles: set("token.go", "middleware.go", "proxy.go", "auth_proxy.go")},
	{name: "internal/bootstrap.critical", floor: 95, goPkgDir: "internal/bootstrap",
		goOnlyFiles: set("realm.go", "seed.go")},
	// internal/livestack is the ONE interlock keeping infra/e2e-*.sh / modules/*/curl-proof.sh /
	// every live-dependent Go test helper from mutating a PUBLIC deployment a human may be
	// actively using (realm redirect URIs reverted, superadmin required-action restored, org
	// tables truncated). It is security-critical by consequence of failure, not by proximity to
	// auth/authz code — a regression here doesn't leak data, it destroys a live human-facing
	// deployment. 95% floor, same as the auth-proximate scopes above.
	{name: "internal/livestack", floor: 95, goPkgDir: "internal/livestack"},
	{name: "web/sdk.auth", floor: 95, webPrefix: "auth/"},

	{name: "cmd/authz", floor: 80, goPkgDir: "cmd/authz"},
	{name: "cmd/bootstrap", floor: 80, goPkgDir: "cmd/bootstrap"},
	{name: "cmd/gateway", floor: 80, goPkgDir: "cmd/gateway"},
	{name: "cmd/identity", floor: 80, goPkgDir: "cmd/identity"},
	{name: "cmd/org", floor: 80, goPkgDir: "cmd/org"},
	{name: "cmd/registry", floor: 80, goPkgDir: "cmd/registry"},
	{name: "internal/authz", floor: 80, goPkgDir: "internal/authz"},
	{name: "internal/authz/fragment", floor: 80, goPkgDir: "internal/authz/fragment"},
	{name: "internal/authz/store", floor: 80, goPkgDir: "internal/authz/store"},
	// internal/authz/client (the shared platform-superadmin AdminAuthorizer org and identity both
	// wrap) is security-relevant S2S client code. floor 80 (general, not security-critical — the
	// security-CRITICAL packages are the 95%-floor set above; this is a thin S2S client wrapper,
	// not the decision engine itself).
	{name: "internal/authz/client", floor: 80, goPkgDir: "internal/authz/client"},
	{name: "internal/config", floor: 80, goPkgDir: "internal/config"},
	{name: "internal/errenv", floor: 80, goPkgDir: "internal/errenv"},
	{name: "internal/gateway.rest", floor: 80, goPkgDir: "internal/gateway",
		goExceptFile: set("token.go", "middleware.go", "proxy.go", "auth_proxy.go")},
	{name: "internal/httpx", floor: 80, goPkgDir: "internal/httpx"},
	{name: "internal/bootstrap.rest", floor: 80, goPkgDir: "internal/bootstrap",
		goExceptFile: set("realm.go", "seed.go")},
	{name: "internal/obs", floor: 80, goPkgDir: "internal/obs"},
	// The Prometheus exposition package. floor 80 (general) — not in the 95%
	// security-critical tier (it observes, never enforces/authorizes). docs_metrics_live_test.go
	// is build-tag-fenced (`live`) and excluded from this scope's measurement the same way every
	// other package's own live-only test files are (go test's default build excludes them).
	{name: "internal/obs/metrics", floor: 80, goPkgDir: "internal/obs/metrics"},
	// Build-identity constants only (no branches) — a visibility scope, same rationale
	// as the modules/*/service/cmd "visibility scope" entries below (measured, gated, never
	// silently ungated, even though there's little to cover).
	{name: "internal/version", floor: 80, goPkgDir: "internal/version"},
	{name: "internal/org", floor: 80, goPkgDir: "internal/org"},
	{name: "internal/registry", floor: 80, goPkgDir: "internal/registry"},
	// The module-artifact validator's own ratchet scope. floor 80 (general, not security-critical) — same as every other package scope.
	{name: "internal/modvalidate", floor: 80, goPkgDir: "internal/modvalidate"},
	// Product module service code, one scope per module. floor 80 (general, not
	// security-critical) — same as every other service scope.
	// The shared module scaffolding the four module services wire (Apache-2.0, root modulekit/).
	{name: "modulekit", floor: 80, goPkgDir: "modulekit"},
	{name: "modules/notification/service", floor: 80, goPkgDir: "modules/notification/service"},
	{name: "modules/timesheet/service", floor: 80, goPkgDir: "modules/timesheet/service"},
	{name: "modules/docs/service", floor: 80, goPkgDir: "modules/docs/service"},
	{name: "modules/helpdesk/service", floor: 80, goPkgDir: "modules/helpdesk/service"},
	// Visibility-only scopes for the four modules' cmd/main.go entry points — the module scopes
	// above only match files directly in modules/*/service, so without these main/run would be
	// completely UNMEASURED, not merely under-floor. One scope per module so `make
	// coverage-report` shows each module's cmd/ coverage on its own line. floor 80 (general, same
	// as the module service scopes themselves); each min in coverage/ratchet.json is that scope's
	// measured baseline, clamped at 0.0.
	{name: "modules/notification/service/cmd", floor: 80, goPkgDir: "modules/notification/service/cmd"},
	{name: "modules/timesheet/service/cmd", floor: 80, goPkgDir: "modules/timesheet/service/cmd"},
	{name: "modules/docs/service/cmd", floor: 80, goPkgDir: "modules/docs/service/cmd"},
	{name: "modules/helpdesk/service/cmd", floor: 80, goPkgDir: "modules/helpdesk/service/cmd"},
	{name: "web/sdk.rest", floor: 80, webExceptPrefix: "auth/"},
	// web/shell: no prefix filter — unlike web/sdk's auth/rest split, web/shell is one scope
	// covering its whole src/ tree (it has no security-critical subset of its own the way
	// web/sdk.auth does).
	{name: "web/shell", floor: 80, webSource: webSourceShell},
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

const goModule = "github.com/rosschiu/kiban"

type stmtCount struct {
	total, covered int
}

func (s stmtCount) pct() float64 {
	if s.total == 0 {
		return 0
	}
	return 100 * float64(s.covered) / float64(s.total)
}

func (s *stmtCount) add(o stmtCount) {
	s.total += o.total
	s.covered += o.covered
}

// loadGoProfile parses a `go test -coverprofile` file into per-file statement counts, keyed by
// the file path relative to the module root (e.g. "internal/gateway/token.go").
func loadGoProfile(path_ string) (map[string]stmtCount, error) {
	profiles, err := cover.ParseProfiles(path_)
	if err != nil {
		return nil, fmt.Errorf("parse go coverprofile %s: %w", path_, err)
	}
	out := make(map[string]stmtCount)
	prefix := goModule + "/"
	for _, p := range profiles {
		rel := strings.TrimPrefix(p.FileName, prefix)
		var c stmtCount
		for _, b := range p.Blocks {
			c.total += b.NumStmt
			if b.Count > 0 {
				c.covered += b.NumStmt
			}
		}
		e := out[rel]
		e.add(c)
		out[rel] = e
	}
	return out, nil
}

type webSummaryEntry struct {
	Statements struct {
		Total   int     `json:"total"`
		Covered int     `json:"covered"`
		Pct     float64 `json:"pct"`
	} `json:"statements"`
}

// loadWebSummary parses vitest's --coverage.reporter=json-summary output. Keys are absolute
// paths; we only care about ones under sdkSrcDir, converted to paths relative to src/.
func loadWebSummary(path_ string, sdkSrcDir string) (map[string]stmtCount, error) {
	data, err := os.ReadFile(path_)
	if err != nil {
		return nil, fmt.Errorf("read web coverage summary %s: %w", path_, err)
	}
	var raw map[string]webSummaryEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse web coverage summary %s: %w", path_, err)
	}
	out := make(map[string]stmtCount)
	if abs, err := filepath.Abs(sdkSrcDir); err == nil {
		sdkSrcDir = abs
	}
	sdkSrcDir = strings.TrimSuffix(sdkSrcDir, "/") + "/"
	for k, v := range raw {
		if k == "total" {
			continue
		}
		if !strings.HasPrefix(k, sdkSrcDir) {
			continue
		}
		rel := strings.TrimPrefix(k, sdkSrcDir)
		out[rel] = stmtCount{total: v.Statements.Total, covered: v.Statements.Covered}
	}
	return out, nil
}

// computeScope aggregates the matching files' statement counts for one scope. webFiles is the
// web/sdk coverage map; webShellFiles is the web/shell one — a scope picks between them via its
// own webSource field (zero value "sdk").
func computeScope(s scopeDef, goFiles map[string]stmtCount, webFiles map[string]stmtCount, webShellFiles map[string]stmtCount) stmtCount {
	var total stmtCount
	if s.goPkgDir != "" {
		for rel, c := range goFiles {
			if path.Dir(rel) != s.goPkgDir {
				continue
			}
			base := path.Base(rel)
			if s.goOnlyFiles != nil && !s.goOnlyFiles[base] {
				continue
			}
			if s.goExceptFile != nil && s.goExceptFile[base] {
				continue
			}
			total.add(c)
		}
		return total
	}
	// web scope
	source := webFiles
	if s.webSource == webSourceShell {
		source = webShellFiles
	}
	for rel, c := range source {
		if s.webPrefix != "" && !strings.HasPrefix(rel, s.webPrefix) {
			continue
		}
		if s.webExceptPrefix != "" && strings.HasPrefix(rel, s.webExceptPrefix) {
			continue
		}
		total.add(c)
	}
	return total
}

type ratchetEntry struct {
	Min   float64 `json:"min"`
	Floor float64 `json:"floor"`
}

func loadRatchet(path_ string) (map[string]ratchetEntry, error) {
	data, err := os.ReadFile(path_)
	if err != nil {
		return nil, fmt.Errorf("read ratchet file %s: %w", path_, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ratchet file %s: %w", path_, err)
	}
	out := make(map[string]ratchetEntry, len(raw))
	for k, v := range raw {
		if strings.HasPrefix(k, "_") {
			continue // e.g. "_comment" — not a scope
		}
		var e ratchetEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, fmt.Errorf("parse ratchet entry %q in %s: %w", k, path_, err)
		}
		out[k] = e
	}
	return out, nil
}

func main() {
	mode := flag.String("mode", "gate", `"gate" (fail below ratchet min) or "report" (always exit 0, show gap-to-floor)`)
	ratchetPath := flag.String("ratchet", "coverage/ratchet.json", "path to coverage/ratchet.json")
	goProfile := flag.String("go-profile", "coverage/go.out", "path to the go test -coverprofile output")
	webSummary := flag.String("web-summary", "web/sdk/coverage/coverage-summary.json", "path to vitest's json-summary coverage output")
	webSrcDir := flag.String("web-src-dir", "web/sdk/src", "the web/sdk src directory (must match the prefix used in coverage-summary.json)")
	webShellSummary := flag.String("web-shell-summary", "web/shell/coverage/coverage-summary.json", "path to web/shell's vitest json-summary coverage output")
	webShellSrcDir := flag.String("web-shell-src-dir", "web/shell/src", "the web/shell src directory (must match the prefix used in its coverage-summary.json)")
	flag.Parse()

	ratchet, err := loadRatchet(*ratchetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	goFiles, err := loadGoProfile(*goProfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	webFiles, err := loadWebSummary(*webSummary, *webSrcDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	webShellFiles, err := loadWebSummary(*webShellSummary, *webShellSrcDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}

	type row struct {
		name                string
		current, min, floor float64
		gapToFloor          float64
		pass                bool
	}
	var rows []row
	missing := false
	for _, s := range scopes {
		re, ok := ratchet[s.name]
		if !ok {
			fmt.Fprintf(os.Stderr, "coveragegate: scope %q has no entry in %s\n", s.name, *ratchetPath)
			missing = true
			continue
		}
		c := computeScope(s, goFiles, webFiles, webShellFiles)
		cur := c.pct()
		rows = append(rows, row{
			name:       s.name,
			current:    cur,
			min:        re.Min,
			floor:      re.Floor,
			gapToFloor: cur - re.Floor,
			pass:       cur >= re.Min,
		})
	}
	if missing {
		os.Exit(2)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	showReport := *mode == "report"
	if showReport {
		fmt.Printf("%-32s %10s %10s %10s %12s\n", "Scope", "Current%", "Min%", "Floor%", "GapToFloor")
	} else {
		fmt.Printf("%-32s %10s %10s %10s %8s\n", "Scope", "Current%", "Min%", "Floor%", "Status")
	}
	allPass := true
	for _, r := range rows {
		if !r.pass {
			allPass = false
		}
		if showReport {
			fmt.Printf("%-32s %9.1f%% %9.1f%% %9.1f%% %+11.1f\n", r.name, r.current, r.min, r.floor, r.gapToFloor)
		} else {
			status := "PASS"
			if !r.pass {
				status = "FAIL"
			}
			fmt.Printf("%-32s %9.1f%% %9.1f%% %9.1f%% %8s\n", r.name, r.current, r.min, r.floor, status)
		}
	}

	if *mode == "gate" && !allPass {
		fmt.Fprintln(os.Stderr, "\ncoverage-gate: one or more scopes fell below their ratchet minimum")
		os.Exit(1)
	}
}
