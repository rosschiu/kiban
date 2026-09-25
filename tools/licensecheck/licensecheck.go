// SPDX-License-Identifier: Apache-2.0

// Package licensecheck implements the SPDX header sweep: every first-party source file
// (Go, TS/TSX, SQL, shell) must carry a `SPDX-License-Identifier: <id>` line matching its
// directory's license, per LICENSING.md's path->license map. This package owns the zone rules
// (which directory gets which SPDX id), the per-extension comment/insertion syntax, and the
// exclusion rules (generated files, node_modules, build output, lockfiles) — both the
// `make license-check` verifier (tools/licensecheck/cmd, check mode) and the one-time sweep that
// applied the headers (same binary, -fix mode) share this single source of truth so the two can
// never silently drift apart.
package licensecheck

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Apache is the one first-party license: the foundation, the sample modules, the SDK, the sample
// shell, the module validator, the differential authz harness and the docs all carry it.
const Apache = "Apache-2.0"

// zoneRule is one (prefix, spdx) entry. Rules are matched longest-prefix-first so a more
// specific zone (e.g. "internal/modvalidate/") wins over a broader one (e.g. "internal/").
type zoneRule struct {
	prefix string
	spdx   string
}

// zones mirrors LICENSING.md's path -> license table exactly; keep the two in sync by hand (this
// package has no way to read markdown at build time, and LICENSING.md is meant for a human
// reader first). Every zone is Apache-2.0 today; the table still names the first-party
// directories so a path outside them is never silently defaulted.
var zones = []zoneRule{
	{"web/sdk/", Apache},
	{"web/shell/", Apache},
	{"modulekit/", Apache},
	{"docs/", Apache},
	{"cmd/", Apache},
	{"internal/", Apache},
	{"migrations/", Apache},
	{"modules/", Apache},
	{"infra/", Apache},
	{"contracts/", Apache},
	{"tools/", Apache},
	{"scripts/", Apache},
}

// excludedDirSegments: a path containing any of these as a path segment is never checked,
// regardless of extension — third-party, build output, or otherwise not first-party source.
var excludedDirSegments = map[string]bool{
	"ports":        true, // not first-party source
	"spike":        true, // not first-party source
	"node_modules": true,
	"dist":         true,
	"coverage":     true,
	".git":         true,
}

// checkedExtensions: the four source kinds the sweep covers (Go, TS/TSX, SQL, shell).
var checkedExtensions = map[string]bool{
	".go":  true,
	".ts":  true,
	".tsx": true,
	".sql": true,
	".sh":  true,
}

// Zone returns the SPDX id a repo-relative path (forward-slash separated, no leading "./")
// belongs to, or "" if the path falls outside every declared zone (caller treats that as "not
// first-party source under this sweep's scope" — never a silent default).
func Zone(relPath string) string {
	best := zoneRule{}
	for _, z := range zones {
		if strings.HasPrefix(relPath, z.prefix) && len(z.prefix) > len(best.prefix) {
			best = z
		}
	}
	return best.spdx
}

// Excluded reports whether relPath should be skipped entirely: outside every zone, in an
// excluded directory, not a checked extension, or a LICENSE file itself.
func Excluded(relPath string) bool {
	if filepath.Base(relPath) == "LICENSE" {
		return true
	}
	for _, seg := range strings.Split(relPath, "/") {
		if excludedDirSegments[seg] {
			return true
		}
	}
	if !checkedExtensions[filepath.Ext(relPath)] {
		return true
	}
	return false
}

// headerLine returns the exact SPDX comment line for an extension (".go"/".ts"/".tsx" use "//",
// ".sql" uses "--", ".sh" uses "#").
func headerLine(ext, spdx string) string {
	switch ext {
	case ".sql":
		return "-- SPDX-License-Identifier: " + spdx
	case ".sh":
		return "# SPDX-License-Identifier: " + spdx
	default:
		return "// SPDX-License-Identifier: " + spdx
	}
}

// isGenerated reports whether data is a Go-tooling "Code generated ... DO NOT EDIT" file (sqlc
// output etc.) — the standard machine-readable marker (golang.org/s/generatedcode), checked
// within the first few lines so a copyright/SPDX header inserted above it by a future run still
// counts as generated.
func isGenerated(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; sc.Scan() && i < 5; i++ {
		if strings.Contains(sc.Text(), "Code generated") && strings.Contains(sc.Text(), "DO NOT EDIT") {
			return true
		}
	}
	return false
}

// HasHeader reports whether data already contains the expected SPDX line anywhere in its first
// 10 lines (headers land at the very top, but a shebang or Go build-tag line may precede it).
func HasHeader(data []byte, want string) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; sc.Scan() && i < 10; i++ {
		if strings.TrimSpace(sc.Text()) == want {
			return true
		}
	}
	return false
}

// Finding is one file's check result.
type Finding struct {
	Path   string // repo-relative
	Status string // "ok" | "missing" | "generated-skip" | "excluded-skip"
	Want   string // expected SPDX line, "" if excluded/generated
}

// Walk visits every file under root, classifying each per the rules above. root is the repo
// root (absolute or relative); returned Finding.Path is always repo-relative, forward-slash.
func Walk(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if excludedDirSegments[d.Name()] || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if Excluded(rel) {
			return nil
		}
		spdx := Zone(rel)
		if spdx == "" {
			return nil // outside every declared zone — not this sweep's concern
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isGenerated(data) {
			findings = append(findings, Finding{Path: rel, Status: "generated-skip"})
			return nil
		}
		want := headerLine(filepath.Ext(rel), spdx)
		if HasHeader(data, want) {
			findings = append(findings, Finding{Path: rel, Status: "ok", Want: want})
		} else {
			findings = append(findings, Finding{Path: rel, Status: "missing", Want: want})
		}
		return nil
	})
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, err
}

// InsertHeader returns data with the SPDX header line inserted at the correct position for its
// extension, preserving a leading shebang (shell) or the file's own content order otherwise
// (Go/TS/SQL: header first, blank line, then original content — safe for a Go file with a
// package-doc comment because the blank line keeps the header from merging into that comment
// while the comment stays immediately before `package`, unchanged).
func InsertHeader(data []byte, ext, want string) []byte {
	content := string(data)
	if ext == ".sh" && strings.HasPrefix(content, "#!") {
		nl := strings.IndexByte(content, '\n')
		if nl == -1 {
			return []byte(content + "\n" + want + "\n")
		}
		shebang, rest := content[:nl+1], content[nl+1:]
		return []byte(shebang + want + "\n\n" + rest)
	}
	return []byte(want + "\n\n" + content)
}

// Fix applies InsertHeader to every "missing" finding under root, in place. Returns the number
// of files changed.
func Fix(root string, findings []Finding) (int, error) {
	n := 0
	for _, f := range findings {
		if f.Status != "missing" {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		data, err := os.ReadFile(full)
		if err != nil {
			return n, fmt.Errorf("read %s: %w", f.Path, err)
		}
		fixed := InsertHeader(data, filepath.Ext(f.Path), f.Want)
		if err := os.WriteFile(full, fixed, 0o644); err != nil {
			return n, fmt.Errorf("write %s: %w", f.Path, err)
		}
		n++
	}
	return n, nil
}
