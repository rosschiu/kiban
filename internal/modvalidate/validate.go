// SPDX-License-Identifier: Apache-2.0

package modvalidate

import "path/filepath"

// ValidateModule runs every module-contract rule that needs only a single module's own
// artifacts (no cross-module/catalog state). Load errors (LoadModule's own return) should be
// reported separately/first — ValidateModule assumes mod.Manifest is non-nil (LoadModule already
// guarantees this or returns a nil *Module).
func ValidateModule(mod *Module) []ValidationError {
	var errs []ValidationError

	if mod.Manifest != nil {
		errs = append(errs, validateManifest(mod.Manifest)...)
		errs = append(errs, validateLicenseFile(mod.Manifest.ModuleKey, mod.Dir, mod.Manifest.License)...)
	}

	if mod.Fragment != nil && mod.Manifest != nil {
		errs = append(errs, validateFragment(mod.Manifest.ModuleKey, mod.Fragment)...)
	}

	if mod.OpenAPI != nil && mod.Manifest != nil {
		errs = append(errs, validateOpenAPI(mod.Manifest.ModuleKey, mod.Manifest.Service.BasePath, mod.OpenAPI)...)
	}

	if mod.Manifest != nil {
		errs = append(errs, validateMigrations(mod.Manifest.ModuleKey, filepath.Join(mod.Dir, "migrations"), mod.Migrations)...)
	}

	if mod.Frontend != nil && mod.Manifest != nil {
		errs = append(errs, validateFrontend(mod.Manifest.ModuleKey, mod.Frontend, mod.Fragment)...)
	}

	return errs
}

// ValidateBatch runs ValidateModule over every module plus every cross-module contract check
// (duplicates across the catalog, dependency graph). snapshot may be zero-valued (no external
// catalog to check against — e.g. a single-module validate-modules run).
func ValidateBatch(modules []*Module, snapshot CatalogSnapshot) []ValidationError {
	var errs []ValidationError
	for _, mod := range modules {
		errs = append(errs, ValidateModule(mod)...)
	}
	errs = append(errs, validateCatalogDuplicates(modules, snapshot)...)
	errs = append(errs, validateDependencyGraph(modules, snapshot)...)
	return errs
}
