// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"sort"

	"github.com/Masterminds/semver/v3"
)

// depNode is one resolvable dependency target — either a module in the current validate batch
// (has its own dependencies, so participates in cycle detection) or an entry from an external
// catalog snapshot (a leaf: modules outside the batch don't get their own dependency edges
// re-validated here — that already happened when THEY were validated).
type depNode struct {
	version      string
	dependencies []ManifestDependency // nil for snapshot-only nodes
}

// validateDependencyGraph rejects "dependency graph invalid: unknown key,
// cycle, unsatisfiable version range" across a full validate batch (+ optional external catalog
// snapshot for resolving dependencies on modules outside the batch). Cycle detection only
// traverses edges between modules IN the batch (a snapshot entry never carries its own
// dependency list — it was already validated when its own module was).
func validateDependencyGraph(modules []*Module, snapshot CatalogSnapshot) []ValidationError {
	var errs []ValidationError

	nodes := map[string]depNode{}
	for _, mod := range modules {
		if mod.Manifest == nil {
			continue
		}
		nodes[mod.Manifest.ModuleKey] = depNode{version: mod.Manifest.Version, dependencies: mod.Manifest.Dependencies}
	}
	for _, e := range snapshot.Modules {
		if _, inBatch := nodes[e.ModuleKey]; inBatch {
			continue // batch always wins over a possibly-stale snapshot entry
		}
		nodes[e.ModuleKey] = depNode{version: e.Version}
	}

	for _, mod := range modules {
		if mod.Manifest == nil {
			continue
		}
		mk := mod.Manifest.ModuleKey
		for _, dep := range mod.Manifest.Dependencies {
			target, ok := nodes[dep.ModuleKey]
			if !ok {
				errs = append(errs, errf(mk, RuleDependencyUnknown,
					"module.manifest.json: dependencies[].moduleKey %q is not a known module (in this batch or the supplied catalog snapshot)", dep.ModuleKey))
				continue
			}
			constraint, err := semver.NewConstraint(dep.VersionRange)
			if err != nil {
				continue // already reported by validateManifest's RuleDependencyRangeSyntax
			}
			targetVersion, err := semver.NewVersion(target.version)
			if err != nil {
				continue // target's own version-format error is reported when IT is validated
			}
			if !constraint.Check(targetVersion) {
				errs = append(errs, errf(mk, RuleDependencyRange,
					"module.manifest.json: dependency %q requires versionRange %q, but its resolved version is %q (unsatisfiable)",
					dep.ModuleKey, dep.VersionRange, target.version))
			}
		}
	}

	if cyclePath := findDependencyCycle(nodes); cyclePath != nil {
		errs = append(errs, errf(cyclePath[0], RuleDependencyCycle,
			"module.manifest.json: dependency cycle detected: %v", formatCycle(cyclePath)))
	}

	return errs
}

// findDependencyCycle runs DFS over the batch's own dependency edges (snapshot-only nodes are
// leaves with no outgoing edges) and returns the first cycle found as a path, or nil.
func findDependencyCycle(nodes map[string]depNode) []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var path []string

	var visit func(key string) []string
	visit = func(key string) []string {
		color[key] = gray
		path = append(path, key)
		for _, dep := range nodes[key].dependencies {
			switch color[dep.ModuleKey] {
			case gray:
				// Found the cycle: return the path from dep.ModuleKey's first occurrence onward.
				for i, p := range path {
					if p == dep.ModuleKey {
						return append(append([]string{}, path[i:]...), dep.ModuleKey)
					}
				}
				return []string{dep.ModuleKey, key, dep.ModuleKey}
			case white:
				if cyc := visit(dep.ModuleKey); cyc != nil {
					return cyc
				}
			}
		}
		path = path[:len(path)-1]
		color[key] = black
		return nil
	}

	// Deterministic order for reproducible error messages.
	var keys []string
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if color[k] == white {
			if cyc := visit(k); cyc != nil {
				return cyc
			}
		}
	}
	return nil
}

func formatCycle(path []string) string {
	s := ""
	for i, p := range path {
		if i > 0 {
			s += " -> "
		}
		s += p
	}
	return s
}
