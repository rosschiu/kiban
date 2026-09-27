// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"os"
	"path/filepath"
	"testing"

	licensetext "github.com/rosschiu/kiban/licenses"
)

// baselineFiles returns a minimal, fully contract-conformant module directory's file contents, keyed
// by path relative to the module dir. Every synthetic reject-rule test starts from this baseline
// and mutates exactly one file/field, so a test failing to trip its target rule (rather than some
// unrelated one) is a real signal, not baseline noise.
func baselineFiles(moduleKey string) map[string]string {
	return map[string]string{
		"module.manifest.json": `{
  "contractVersion": "1",
  "moduleKey": "` + moduleKey + `",
  "displayName": "Widget",
  "version": "1.0.0",
  "scopeType": "company",
  "mandatory": false,
  "service": { "basePath": "/api/` + moduleKey + `", "port": 8300, "healthPath": "/health", "image": null },
  "dependencies": [],
  "org": { "requiredOrgUnitTypes": ["company"], "usesMembers": false, "usesPositions": false },
  "data": { "postgresSchema": "` + moduleKey + `", "migrationsPath": "migrations" },
  "license": { "class": "foundation", "spdx": "Apache-2.0", "entitlementRequired": false },
  "events": null
}`,
		"authz.fragment.json": `{
  "moduleKey": "` + moduleKey + `",
  "roles": [
    { "roleKey": "` + moduleKey + `_admin", "label": "Admin", "scopeType": "company",
      "grantsShellAccess": true, "seedCompanyCreatorRole": true, "sortOrder": 10 }
  ],
  "objects": [
    { "objectType": "` + moduleKey + `_item", "label": "Item", "scopeKind": "object",
      "parentKind": "company_module", "managerRelation": "owner",
      "grantableRelations": ["owner", "viewer"], "showInPermissionUi": true, "sortOrder": 10 }
  ],
  "relations": {
    "` + moduleKey + `_item": {
      "company_module": { "this": true },
      "owner": { "this": true },
      "viewer": { "union": [{ "this": true }, { "computedUserset": "owner" }] }
    }
  },
  "features": [
    { "featureKey": "` + moduleKey + `.items.manage", "label": "Manage items", "scopeType": "company",
      "requiresCompany": true, "accessRuleKind": "relation",
      "accessRulePayload": { "objectType": "company_module", "relation": "admin" },
      "sortOrder": 10, "isSidebarEntry": true }
  ],
  "fieldCatalog": [],
  "fieldSets": [],
  "rowScopes": [ { "entityType": "` + moduleKey + `_item", "rules": ["all"] } ],
  "bootstrapPolicy": { "seedCompanyCreatorObjectRelations": [] }
}`,
		"openapi.yaml": `openapi: 3.0.3
info:
  title: Widget module API
  version: "1.0.0"
servers:
  - url: /api/` + moduleKey + `
paths:
  /health:
    get:
      operationId: getHealth
  /v1/items:
    get:
      operationId: listItems
      x-required-modules: [` + moduleKey + `]
`,
		"migrations/0001_init.sql": `CREATE SCHEMA ` + moduleKey + ` AUTHORIZATION kiban;

GRANT USAGE ON SCHEMA ` + moduleKey + ` TO kiban_` + moduleKey + `;
`,
		"frontend/frontend.manifest.json": `{
  "moduleKey": "` + moduleKey + `",
  "routeBase": "/app/` + moduleKey + `",
  "routes": [ { "id": "items", "path": "", "featureKey": "` + moduleKey + `.items.manage" } ],
  "navFromFeatures": true,
  "sdkVersionRange": ">=0.1.0 <1.0.0",
  "remoteEntryUrl": null
}`,
		// Baseline's manifest declares license.class "foundation"/license.spdx "Apache-2.0", so
		// the baseline LICENSE file must byte-match the real canonical text for validateLicenseFile
		// (license-file-class-mismatch) to pass by default — dedicated tests for that rule
		// override/remove this entry.
		"LICENSE": string(licensetext.Apache20),
	}
}

// writeModule materializes a file-content map (baselineFiles, optionally mutated by the caller)
// under dir, creating parent directories as needed.
func writeModule(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

// cloneFiles returns a shallow copy of a baseline file map so a test can override one entry
// without mutating shared state between table cases.
func cloneFiles(base map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	for k, v := range base {
		out[k] = v
	}
	return out
}

// mustLoadAndValidate loads+validates a single module dir and fails the test loudly if the
// module itself failed to load (a load failure is never what a reject-rule test wants to prove —
// it should prove ValidateModule's own semantic rejection).
func mustLoadAndValidate(t *testing.T, dir string) []ValidationError {
	t.Helper()
	mod, loadErrs := LoadModule(dir)
	if mod == nil {
		t.Fatalf("LoadModule(%s) returned nil module; load errors: %v", dir, loadErrs)
	}
	if len(loadErrs) > 0 {
		t.Fatalf("LoadModule(%s): unexpected load errors: %v", dir, loadErrs)
	}
	return ValidateModule(mod)
}

func hasRule(errs []ValidationError, rule string) bool {
	for _, e := range errs {
		if e.Rule == rule {
			return true
		}
	}
	return false
}
