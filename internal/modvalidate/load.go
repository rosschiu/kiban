// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeStrict decodes JSON into v, rejecting any field not present on v's type (unknown fields
// are hard errors at validation time — never silently dropped), EXCEPT object keys prefixed with "_" anywhere in the document, which are treated as
// author comments/annotations — the convention modules/notification/frontend/frontend.manifest.json
// already uses ("_comment", "_featureKeyComment") to document a contract workaround. This is the
// one exemption.
func decodeStrict(data []byte, v any) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	cleaned := stripComments(raw)
	buf, err := json.Marshal(cleaned)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func stripComments(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if strings.HasPrefix(k, "_") {
				continue
			}
			out[k] = stripComments(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = stripComments(val)
		}
		return out
	default:
		return v
	}
}

var migrationFilenamePattern = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// LoadModule reads a module directory's artifacts from disk. It returns load errors (missing
// required artifact, malformed JSON/YAML, unknown fields) as ValidationErrors so callers can
// batch them alongside semantic validation errors; a nil *Module is returned only when the
// manifest itself could not be loaded at all (nothing else can be meaningfully checked).
func LoadModule(dir string) (*Module, []ValidationError) {
	var errs []ValidationError
	mod := &Module{Dir: dir}

	manifestPath := filepath.Join(dir, "module.manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, []ValidationError{errf("", "load-manifest", "%s: %v", manifestPath, err)}
	}
	var m Manifest
	if err := decodeStrict(manifestData, &m); err != nil {
		return nil, []ValidationError{decodeErrToValidation("", manifestPath, err)}
	}
	mod.Manifest = &m
	mod.ModuleKey = m.ModuleKey

	fragmentPath := filepath.Join(dir, "authz.fragment.json")
	fragmentData, err := os.ReadFile(fragmentPath)
	if err != nil {
		errs = append(errs, errf(mod.ModuleKey, "load-fragment", "%s: %v", fragmentPath, err))
	} else {
		var f AuthzFragment
		if err := decodeStrict(fragmentData, &f); err != nil {
			errs = append(errs, decodeErrToValidation(mod.ModuleKey, fragmentPath, err))
		} else {
			mod.Fragment = &f
		}
	}

	openapiPath := filepath.Join(dir, "openapi.yaml")
	openapiData, err := os.ReadFile(openapiPath)
	if err != nil {
		errs = append(errs, errf(mod.ModuleKey, "load-openapi", "%s: %v", openapiPath, err))
	} else {
		var doc map[string]any
		if err := yaml.Unmarshal(openapiData, &doc); err != nil {
			errs = append(errs, errf(mod.ModuleKey, "load-openapi", "%s: %v", openapiPath, err))
		} else {
			mod.OpenAPI = doc
			mod.OpenAPIRaw = openapiData
		}
	}

	var migErrs []ValidationError
	mod.Migrations, migErrs = LoadMigrationsDir(mod.ModuleKey, filepath.Join(dir, "migrations"))
	errs = append(errs, migErrs...)

	frontendManifestPath := filepath.Join(dir, "frontend", "frontend.manifest.json")
	if data, err := os.ReadFile(frontendManifestPath); err == nil {
		var fm FrontendManifest
		if err := decodeStrict(data, &fm); err != nil {
			errs = append(errs, decodeErrToValidation(mod.ModuleKey, frontendManifestPath, err))
		} else {
			mod.Frontend = &fm
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, errf(mod.ModuleKey, "load-frontend", "%s: %v", frontendManifestPath, err))
	}
	// A missing frontend/ dir is not an error — frontend/ is optional (headless modules are
	// first-class).

	return mod, errs
}

func decodeErrToValidation(moduleKey, path string, err error) ValidationError {
	msg := err.Error()
	if strings.Contains(msg, "unknown field") {
		return errf(moduleKey, RuleUnknownField, "%s: %v", path, err)
	}
	return errf(moduleKey, "load-json", "%s: %v", path, err)
}

// LoadCatalogSnapshot reads an external catalog snapshot JSON file (duplicate checks are
// "across the catalog", not just the current validate batch). A missing
// path is not an error — it simply means no external catalog is being checked against (e.g. a
// single-module validate-modules run with no other modules to collide with yet).
func LoadCatalogSnapshot(path string) (CatalogSnapshot, error) {
	if path == "" {
		return CatalogSnapshot{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CatalogSnapshot{}, fmt.Errorf("read catalog snapshot %s: %w", path, err)
	}
	var snap CatalogSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return CatalogSnapshot{}, fmt.Errorf("parse catalog snapshot %s: %w", path, err)
	}
	return snap, nil
}
