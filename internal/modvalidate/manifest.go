// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// moduleKeyPattern mirrors internal/registry/seed.go's own pattern ("[a-z][a-z0-9_]{1,31},
// globally unique"). Duplicated rather than imported: internal/registry
// is a service package this validator has no business depending on, and the pattern is part of
// the contract itself, not registry-owned behavior.
var moduleKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// allowedContractVersions is the set of contractVersion values this build of the validator
// accepts. The module contract is frozen at v1 (the pre-freeze value was "0"). A module declaring
// any other value is rejected loudly, never silently coerced.
var allowedContractVersions = map[string]bool{"1": true}

var allowedScopeTypes = map[string]bool{"global": true, "company": true}
var allowedLicenseClasses = map[string]bool{"foundation": true, "open": true}

// licenseClassAllowedSPDX is the canonical class -> allowed license.spdx values map, so a
// manifest cannot declare e.g. license.class "foundation" with an arbitrary/wrong/GPL
// license.spdx. "foundation" is exactly Apache-2.0 (the licence of the whole first-party tree,
// LICENSE/licenses/Apache-2.0.txt); "open" is Apache-2.0 or MIT (the two sanctioned open
// choices).
var licenseClassAllowedSPDX = map[string]map[string]bool{
	"foundation": {"Apache-2.0": true},
	"open":       {"Apache-2.0": true, "MIT": true},
}

// validateManifest runs every module.manifest.json contract rule that needs only the manifest
// itself (no cross-artifact or cross-module state).
func validateManifest(m *Manifest) []ValidationError {
	var errs []ValidationError
	mk := m.ModuleKey

	if !allowedContractVersions[m.ContractVersion] {
		errs = append(errs, errf(mk, RuleUnknownContractVersion,
			"module.manifest.json: contractVersion %q is not a known contract version", m.ContractVersion))
	}

	if !moduleKeyPattern.MatchString(m.ModuleKey) {
		errs = append(errs, errf(mk, RuleModuleKeyFormat,
			"module.manifest.json: moduleKey %q does not match %s", m.ModuleKey, moduleKeyPattern.String()))
	}

	if !allowedScopeTypes[m.ScopeType] {
		errs = append(errs, errf(mk, RuleScopeTypeInvalid,
			"module.manifest.json: scopeType %q must be \"global\" or \"company\"", m.ScopeType))
	}

	// The cheap structural rules the contract states but nothing
	// checked — port range (uniqueness is a catalog rule, catalog.go), healthPath shape, and
	// dependencies[].required (v1 semantics: every declared dependency is required — the registry
	// resolves all dependency rows as required — so false is refused rather than silently ignored).
	if m.Service.Port < 1 || m.Service.Port > 65535 {
		errs = append(errs, errf(mk, RuleServicePort,
			"module.manifest.json: service.port %d must be in 1..65535", m.Service.Port))
	}
	if !strings.HasPrefix(m.Service.HealthPath, "/") {
		errs = append(errs, errf(mk, RuleHealthPath,
			"module.manifest.json: service.healthPath %q must be a non-empty absolute path", m.Service.HealthPath))
	}
	for _, dep := range m.Dependencies {
		if !dep.Required {
			errs = append(errs, errf(mk, RuleDependencyRequired,
				"module.manifest.json: dependencies[%s].required must be true — contract v1 has no optional dependencies (the registry treats every dependency as required)", dep.ModuleKey))
		}
	}

	if _, err := semver.NewVersion(m.Version); err != nil {
		errs = append(errs, errf(mk, RuleVersionFormat, "module.manifest.json: version %q is not valid semver: %v", m.Version, err))
	}

	wantBasePath := "/api/" + m.ModuleKey
	if m.Service.BasePath != wantBasePath {
		errs = append(errs, errf(mk, RuleBasePathMismatch,
			"module.manifest.json: service.basePath %q must equal %q (moduleKey %q)", m.Service.BasePath, wantBasePath, m.ModuleKey))
	}

	if m.Data.PostgresSchema != m.ModuleKey {
		errs = append(errs, errf(mk, RuleSchemaMismatch,
			"module.manifest.json: data.postgresSchema %q must equal moduleKey %q", m.Data.PostgresSchema, m.ModuleKey))
	}

	if !allowedLicenseClasses[m.License.Class] {
		errs = append(errs, errf(mk, "license-class-invalid",
			"module.manifest.json: license.class %q must be \"foundation\" or \"open\"", m.License.Class))
	} else if allowed := licenseClassAllowedSPDX[m.License.Class]; !allowed[m.License.SPDX] {
		errs = append(errs, errf(mk, RuleLicenseSPDXInvalid,
			"module.manifest.json: license.spdx %q is not a canonical id for license.class %q (allowed: %v)",
			m.License.SPDX, m.License.Class, slices.Sorted(maps.Keys(allowed))))
	}

	for _, dep := range m.Dependencies {
		if !moduleKeyPattern.MatchString(dep.ModuleKey) {
			errs = append(errs, errf(mk, RuleModuleKeyFormat,
				"module.manifest.json: dependencies[].moduleKey %q does not match %s", dep.ModuleKey, moduleKeyPattern.String()))
			continue
		}
		if _, err := semver.NewConstraint(dep.VersionRange); err != nil {
			errs = append(errs, errf(mk, RuleDependencyRangeSyntax,
				"module.manifest.json: dependencies[%s].versionRange %q is not a valid semver range: %v", dep.ModuleKey, dep.VersionRange, err))
		}
	}

	return errs
}
