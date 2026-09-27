// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNotificationModulePasses is the conformance suite's positive case: the real, shipped
// modules/notification directory must pass every contract check with zero named errors.
func TestNotificationModulePasses(t *testing.T) {
	dir := repoPath(t, "modules", "notification")
	mod, loadErrs := LoadModule(dir)
	if mod == nil {
		t.Fatalf("LoadModule(%s) returned nil; load errors: %v", dir, loadErrs)
	}
	if len(loadErrs) > 0 {
		t.Fatalf("LoadModule(%s): unexpected load errors: %v", dir, loadErrs)
	}
	errs := ValidateModule(mod)
	if len(errs) > 0 {
		t.Fatalf("notification module must pass §8 validation; got %d error(s):\n%s", len(errs), joinErrs(errs))
	}
}

func joinErrs(errs []ValidationError) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return b.String()
}

func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine caller for repo root lookup")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(append([]string{root}, parts...)...)
}

// TestValidateModule_RejectRules is the conformance suite: one synthetic bad-module fixture per
// reject rule, each named error asserted (never assuming a fixed module list).
func TestValidateModule_RejectRules(t *testing.T) {
	cases := []struct {
		name   string
		rule   string
		mutate func(files map[string]string)
	}{
		{
			name: "unknown field in manifest",
			rule: RuleUnknownField,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"],
					`"events": null`, `"events": null, "unexpectedField": true`, 1)
			},
		},
		{
			name: "unknown contractVersion",
			rule: RuleUnknownContractVersion,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"contractVersion": "1"`, `"contractVersion": "7"`, 1)
			},
		},
		{
			name: "bad moduleKey format",
			rule: RuleModuleKeyFormat,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"moduleKey": "widget"`, `"moduleKey": "Widget9"`, 1)
			},
		},
		{
			name: "basePath mismatch",
			rule: RuleBasePathMismatch,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"basePath": "/api/widget"`, `"basePath": "/api/wrong"`, 1)
			},
		},
		{
			name: "schema mismatch",
			rule: RuleSchemaMismatch,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"postgresSchema": "widget"`, `"postgresSchema": "wrongschema"`, 1)
			},
		},
		{
			name: "license file class mismatch",
			rule: RuleLicenseFileClassMismatch,
			mutate: func(f map[string]string) {
				// Manifest still declares "foundation"/Apache-2.0, but the module's own
				// LICENSE file carries a truncated stub instead of the canonical text — the
				// drift case (a module's LICENSE file edited or replaced).
				f["LICENSE"] = "Apache License\nVersion 2.0, January 2004\n"
			},
		},
		{
			name: "license file missing",
			rule: RuleLicenseFileClassMismatch,
			mutate: func(f map[string]string) {
				delete(f, "LICENSE")
			},
		},
		{
			// license.spdx must be a canonical id for its class — a
			// manifest declaring "foundation" with an arbitrary/wrong SPDX id (here a copyleft
			// one) must be rejected even though license.class itself is valid.
			name: "license spdx wrong class for text (GPL declared)",
			rule: RuleLicenseSPDXInvalid,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"spdx": "Apache-2.0"`, `"spdx": "GPL-3.0-only"`, 1)
			},
		},
		{
			// license.class "open" with an unlisted spdx is not canonical either — "open"
			// must be exactly Apache-2.0 or MIT, never left arbitrary.
			name: "license spdx invalid for open class",
			rule: RuleLicenseSPDXInvalid,
			mutate: func(f map[string]string) {
				m := f["module.manifest.json"]
				m = strings.Replace(m, `"class": "foundation"`, `"class": "open"`, 1)
				m = strings.Replace(m, `"spdx": "Apache-2.0"`, `"spdx": "BSD-3-Clause"`, 1)
				f["module.manifest.json"] = m
			},
		},
		{
			name: "bad version format",
			rule: RuleVersionFormat,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"version": "1.0.0"`, `"version": "not-a-version"`, 1)
			},
		},
		{
			name: "dependency version range syntax",
			rule: RuleDependencyRangeSyntax,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"],
					`"dependencies": []`,
					`"dependencies": [{"moduleKey": "other", "versionRange": "not-a-range", "required": true}]`, 1)
			},
		},
		{
			name: "fragment moduleKey mismatch",
			rule: RuleFragmentModuleKeyMismatch,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"moduleKey": "widget"`, `"moduleKey": "different"`, 1)
			},
		},
		{
			name: "feature key prefix mismatch",
			rule: RuleFeaturePrefixMismatch,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"featureKey": "widget.items.manage"`, `"featureKey": "other.items.manage"`, 1)
				// keep frontend's route in sync so this test isolates the fragment-side rule
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"], `"featureKey": "widget.items.manage"`, `"featureKey": "other.items.manage"`, 1)
			},
		},
		{
			name: "authz relation outside subset wall",
			rule: RuleAuthzSubsetWall,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"viewer": { "union": [{ "this": true }, { "computedUserset": "owner" }] }`,
					`"viewer": { "intersection": [{ "this": true }, { "computedUserset": "owner" }] }`, 1)
			},
		},
		{
			name: "authz fragment redeclares a platform base type",
			rule: RuleAuthzBaseTypeRedeclared,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"relations": {`,
					`"relations": {
    "company_module": { "bogus": { "this": true } },`, 1)
			},
		},
		{
			// Company-anchor contract rule: every declared object type carries the `company_module`
			// anchor the decision layer binds object checks through; a computed (non-`this`)
			// definition is refused too, since no tuple could ever be written for it.
			name: "authz object type without company_module anchor",
			rule: RuleAuthzAnchorMissing,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"company_module": { "this": true },`, ``, 1)
			},
		},
		{
			name: "authz company_module anchor is not a direct relation",
			rule: RuleAuthzAnchorMissing,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"company_module": { "this": true },`, `"company_module": { "computedUserset": "owner" },`, 1)
			},
		},
		{
			// Dangling access rule: a feature anchored on a relation the effective model does not
			// define (here `company_module#bogus`) can never match and is refused at install.
			name: "authz access rule relation not in effective model",
			rule: RuleAuthzRelationUnknown,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"accessRulePayload": { "objectType": "company_module", "relation": "admin" }`,
					`"accessRulePayload": { "objectType": "company_module", "relation": "bogus" }`, 1)
			},
		},
		{
			// A cross-type tupleToUserset whose computedUserset exists on
			// no type of the effective model (notification's former `company_module#member`).
			name: "authz tupleToUserset target not in effective model",
			rule: RuleAuthzRelationUnknown,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"],
					`"owner": { "this": true },`,
					`"owner": { "this": true },
      "company_module": { "this": true },
      "reader": { "tupleToUserset": { "tupleset": "company_module", "computedUserset": "nonexistent" } },`, 1)
			},
		},
		{
			name: "migration bad filename",
			rule: RuleMigrationFilename,
			mutate: func(f map[string]string) {
				f["migrations/not-numbered.sql"] = "-- not a contract-shaped filename\n"
			},
		},
		{
			name: "migration duplicate number",
			rule: RuleMigrationOrder,
			mutate: func(f map[string]string) {
				f["migrations/0001_dup.sql"] = "-- duplicate migration number 0001\n"
			},
		},
		{
			name: "migration cross-schema reference",
			rule: RuleMigrationCrossSchema,
			mutate: func(f map[string]string) {
				f["migrations/0001_init.sql"] += "\nCREATE TABLE other_module.leaked (id int);\n"
			},
		},
		{
			name: "migration edited after checksum recorded",
			rule: RuleMigrationChecksum,
			mutate: func(f map[string]string) {
				f["migrations/checksums.json"] = `{"checksums": {"0001_init.sql": "0000000000000000000000000000000000000000000000000000000000000000"}}`
			},
		},
		{
			name: "openapi missing operationId",
			rule: RuleOpenAPIOperationID,
			mutate: func(f map[string]string) {
				f["openapi.yaml"] = strings.Replace(f["openapi.yaml"], "      operationId: listItems\n", "", 1)
			},
		},
		{
			name: "openapi path outside basePath",
			rule: RuleOpenAPIPathOutsideBasePath,
			mutate: func(f map[string]string) {
				f["openapi.yaml"] = strings.Replace(f["openapi.yaml"], "  - url: /api/widget", "  - url: /api/other", 1)
			},
		},
		{
			name: "openapi missing capability annotation",
			rule: RuleOpenAPIMissingCapabilityAnnotation,
			mutate: func(f map[string]string) {
				f["openapi.yaml"] = strings.Replace(f["openapi.yaml"], "      x-required-modules: [widget]\n", "", 1)
			},
		},
		// The ledger lists every file — a deleted/renamed shipped
		// migration, an unrecorded new one, or a missing ledger all fail.
		{
			name: "migration deleted after checksum recorded",
			rule: RuleMigrationChecksum,
			mutate: func(f map[string]string) {
				f["migrations/checksums.json"] = `{"checksums": {"0001_init.sql": "x", "0002_gone.sql": "y"}}`
			},
		},
		{
			name: "migration not recorded in ledger",
			rule: RuleMigrationChecksum,
			mutate: func(f map[string]string) {
				f["migrations/checksums.json"] = `{"checksums": {}}`
			},
		},
		{
			name: "migration ledger missing",
			rule: RuleMigrationChecksum,
			mutate: func(f map[string]string) {
				delete(f, "migrations/checksums.json")
			},
		},
		// Statement kinds the leading-verb regex never saw.
		{
			name: "migration unsafe statement",
			rule: RuleMigrationUnsafeStatement,
			mutate: func(f map[string]string) {
				f["migrations/0001_init.sql"] += "\nGRANT kiban TO kiban_widget;\n"
			},
		},
		{
			name: "migration public table",
			rule: RuleMigrationCrossSchema,
			mutate: func(f map[string]string) {
				f["migrations/0001_init.sql"] += "\nCREATE TABLE public.leak (id int);\n"
			},
		},
		// Structural contract rules.
		{
			name: "service port out of range",
			rule: RuleServicePort,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"port": 8300`, `"port": 0`, 1)
			},
		},
		{
			name: "healthPath not absolute",
			rule: RuleHealthPath,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"healthPath": "/health"`, `"healthPath": ""`, 1)
			},
		},
		{
			name: "scopeType empty",
			rule: RuleScopeTypeInvalid,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"], `"scopeType": "company"`, `"scopeType": ""`, 1)
			},
		},
		{
			name: "dependency required false",
			rule: RuleDependencyRequired,
			mutate: func(f map[string]string) {
				f["module.manifest.json"] = strings.Replace(f["module.manifest.json"],
					`"dependencies": []`, `"dependencies": [{"moduleKey": "other", "versionRange": ">=1.0.0", "required": false}]`, 1)
			},
		},
		{
			name: "fragment object grantableRelations unknown",
			rule: RuleFragmentObjectInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"grantableRelations": ["owner", "viewer"]`, `"grantableRelations": ["owner", "nonexistent"]`, 1)
			},
		},
		{
			name: "fragment object managerRelation unknown",
			rule: RuleFragmentObjectInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"managerRelation": "owner"`, `"managerRelation": "nope"`, 1)
			},
		},
		{
			name: "fragment object parentKind unknown",
			rule: RuleFragmentObjectInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"parentKind": "company_module"`, `"parentKind": "galaxy"`, 1)
			},
		},
		{
			name: "fragment object scopeKind unknown",
			rule: RuleFragmentObjectInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"scopeKind": "object"`, `"scopeKind": "galaxy"`, 1)
			},
		},
		{
			name: "fragment object not in relations",
			rule: RuleFragmentObjectInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"objectType": "widget_item"`, `"objectType": "widget_other"`, 1)
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"entityType": "widget_item"`, `"entityType": "widget_other"`, 1)
			},
		},
		{
			name: "fragment feature scopeType unknown",
			rule: RuleFragmentFeatureInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"label": "Manage items", "scopeType": "company"`, `"label": "Manage items", "scopeType": "galaxy"`, 1)
			},
		},
		{
			name: "fragment feature accessRuleKind unknown",
			rule: RuleFragmentFeatureInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"accessRuleKind": "relation"`, `"accessRuleKind": "magic"`, 1)
			},
		},
		{
			name: "fragment role scopeType unknown",
			rule: RuleFragmentRoleInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"label": "Admin", "scopeType": "company"`, `"label": "Admin", "scopeType": "galaxy"`, 1)
			},
		},
		{
			name: "fragment rowScopes entityType unknown",
			rule: RuleFragmentRowScopeInvalid,
			mutate: func(f map[string]string) {
				f["authz.fragment.json"] = strings.Replace(f["authz.fragment.json"], `"entityType": "widget_item"`, `"entityType": "nope"`, 1)
			},
		},
		{
			name: "frontend sdkVersionRange garbage",
			rule: RuleFrontendSDKVersionRange,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"], `"sdkVersionRange": ">=0.1.0 <1.0.0"`, `"sdkVersionRange": "garbage"`, 1)
			},
		},
		{
			name: "openapi absolute foreign path key",
			rule: RuleOpenAPIPathOutsideBasePath,
			mutate: func(f map[string]string) {
				f["openapi.yaml"] += "  /api/helpdesk/v1/tickets:\n    get:\n      operationId: leak\n      x-required-modules: [widget]\n"
			},
		},
		{
			name: "openapi second server not root",
			rule: RuleOpenAPIPathOutsideBasePath,
			mutate: func(f map[string]string) {
				f["openapi.yaml"] = strings.Replace(f["openapi.yaml"], "  - url: /api/widget\n", "  - url: /api/widget\n  - url: /api/other\n", 1)
			},
		},
		{
			name: "frontend routeBase mismatch",
			rule: RuleRouteBaseMismatch,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"], `"routeBase": "/app/widget"`, `"routeBase": "/app/wrong"`, 1)
			},
		},
		{
			name: "frontend duplicate route id",
			rule: RuleFrontendDuplicateRouteID,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"],
					`"routes": [ { "id": "items", "path": "", "featureKey": "widget.items.manage" } ]`,
					`"routes": [ { "id": "items", "path": "", "featureKey": "widget.items.manage" }, { "id": "items", "path": "other", "featureKey": "widget.items.manage" } ]`, 1)
			},
		},
		{
			name: "frontend path collision",
			rule: RuleFrontendPathCollision,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"],
					`"routes": [ { "id": "items", "path": "", "featureKey": "widget.items.manage" } ]`,
					`"routes": [ { "id": "items", "path": "shared", "featureKey": "widget.items.manage" }, { "id": "items2", "path": "shared", "featureKey": "widget.items.manage" } ]`, 1)
			},
		},
		{
			name: "frontend bad param name",
			rule: RuleFrontendBadParamName,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"],
					`"path": ""`, `"path": "items/:1bad"`, 1)
			},
		},
		{
			name: "frontend feature key missing from fragment",
			rule: RuleFrontendFeatureKeyMissing,
			mutate: func(f map[string]string) {
				f["frontend/frontend.manifest.json"] = strings.Replace(f["frontend/frontend.manifest.json"], `"featureKey": "widget.items.manage"`, `"featureKey": "widget.nonexistent.key"`, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := cloneFiles(baselineFiles("widget"))
			tc.mutate(files)
			dir := t.TempDir()
			writeModule(t, dir, files)

			// A handful of rules (unknown fields, unknown contractVersion when the manifest
			// itself is otherwise unparseable) surface as LoadModule errors rather than
			// ValidateModule errors, when the offending artifact is the manifest itself — the
			// manifest must parse before ValidateModule can run at all. Combine both error
			// sources so the table doesn't need to know which stage catches which rule.
			mod, loadErrs := LoadModule(dir)
			var errs []ValidationError
			errs = append(errs, loadErrs...)
			if mod != nil {
				errs = append(errs, ValidateModule(mod)...)
			}
			if !hasRule(errs, tc.rule) {
				t.Fatalf("expected rule %q among errors, got:\n%s", tc.rule, joinErrs(errs))
			}
		})
	}
}

// TestValidateModule_BaselineFixturePasses proves the shared baseline itself is contract-clean (so
// every reject-rule case above trips ONLY its own mutation, not baseline noise).
func TestValidateModule_BaselineFixturePasses(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, baselineFiles("widget"))
	// The baseline has no checksums.json ledger yet, so write one first (module-owned artifact;
	// migrations are immutable once released — nothing to compare against pre-release).
	mod, loadErrs := LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("baseline fixture failed to load: %v", loadErrs)
	}
	if err := WriteChecksumLedger(dir, mod); err != nil {
		t.Fatalf("WriteChecksumLedger: %v", err)
	}
	errs := mustLoadAndValidate(t, dir)
	if len(errs) > 0 {
		t.Fatalf("baseline fixture must be §8-clean; got:\n%s", joinErrs(errs))
	}
}

// TestValidateModule_ReadyProbeExempt proves /ready (handleReady's readiness probe — DB ping,
// unauthenticated, same shape as /health) is exempt from the module-scoped x-required-modules
// capability annotation requirement, same as /health (isHealthProbe in openapi.go), so a genuine
// infra probe never needs an annotation.
func TestValidateModule_ReadyProbeExempt(t *testing.T) {
	dir := t.TempDir()
	files := baselineFiles("widget")
	files["openapi.yaml"] = strings.Replace(files["openapi.yaml"], "  /v1/items:", "  /ready:\n    get:\n      operationId: getReady\n  /v1/items:", 1)
	writeModule(t, dir, files)
	mod, loadErrs := LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("fixture failed to load: %v", loadErrs)
	}
	if err := WriteChecksumLedger(dir, mod); err != nil {
		t.Fatalf("WriteChecksumLedger: %v", err)
	}
	errs := mustLoadAndValidate(t, dir)
	for _, e := range errs {
		if e.Rule == RuleOpenAPIMissingCapabilityAnnotation {
			t.Fatalf("expected /ready to be exempt from the capability-annotation rule; got:\n%s", joinErrs(errs))
		}
	}
}

// TestValidateBatch_NotificationAlonePasses exercises the public ValidateBatch entry point (the
// one `cmd/modvalidate` itself calls) end-to-end against the real notification module with no
// external catalog — the single-module `make validate-modules` shape.
func TestValidateBatch_NotificationAlonePasses(t *testing.T) {
	dir := repoPath(t, "modules", "notification")
	mod, loadErrs := LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("load errors: %v", loadErrs)
	}
	errs := ValidateBatch([]*Module{mod}, CatalogSnapshot{})
	if len(errs) > 0 {
		t.Fatalf("ValidateBatch on notification alone must be clean; got:\n%s", joinErrs(errs))
	}
}

// TestValidateBatch_CatalogDuplicates proves the cross-module "duplicate ... across the catalog"
// rules using a synthetic two-module catalog, never assuming a fixed module list.
func TestValidateBatch_CatalogDuplicates(t *testing.T) {
	dirA := t.TempDir()
	writeModule(t, dirA, baselineFiles("alpha"))
	dirB := t.TempDir()
	filesB := cloneFiles(baselineFiles("beta"))
	// Force collisions: same basePath, same route id, same feature key, same object type as alpha.
	filesB["module.manifest.json"] = strings.Replace(filesB["module.manifest.json"], `"basePath": "/api/beta"`, `"basePath": "/api/alpha"`, 1)
	filesB["authz.fragment.json"] = strings.Replace(filesB["authz.fragment.json"], `"featureKey": "beta.items.manage"`, `"featureKey": "alpha.items.manage"`, 1)
	filesB["authz.fragment.json"] = strings.Replace(filesB["authz.fragment.json"], `"objectType": "beta_item"`, `"objectType": "alpha_item"`, 1)
	filesB["frontend/frontend.manifest.json"] = strings.Replace(filesB["frontend/frontend.manifest.json"], `"id": "items"`, `"id": "items"`, 1) // route id "items" already shared with alpha
	writeModule(t, dirB, filesB)

	modA, lA := LoadModule(dirA)
	modB, lB := LoadModule(dirB)
	if modA == nil || modB == nil {
		t.Fatalf("load errors: A=%v B=%v", lA, lB)
	}
	errs := validateCatalogDuplicates([]*Module{modA, modB}, CatalogSnapshot{})
	for _, rule := range []string{RuleDuplicateBasePath, RuleDuplicateRouteID, RuleDuplicateFeatureKey, RuleDuplicateObjectType} {
		if !hasRule(errs, rule) {
			t.Errorf("expected rule %q among catalog duplicate errors, got:\n%s", rule, joinErrs(errs))
		}
	}
}

// TestValidateBatch_PortAndRequiredModules covers the two catalog-level rules: a port claimed
// by two modules (batch or snapshot), and an x-required-modules entry naming an unknown module.
func TestValidateBatch_PortAndRequiredModules(t *testing.T) {
	dirA := t.TempDir()
	filesA := cloneFiles(baselineFiles("alpha"))
	filesA["openapi.yaml"] = strings.Replace(filesA["openapi.yaml"], "x-required-modules: [alpha]", "x-required-modules: [alpha, ghost]", 1)
	writeModule(t, dirA, filesA)
	modA, lA := LoadModule(dirA)
	if modA == nil {
		t.Fatalf("load errors: %v", lA)
	}
	snapshot := CatalogSnapshot{Modules: []CatalogEntry{{ModuleKey: "beta", Version: "1.0.0", BasePath: "/api/beta", Port: 8300}}}
	errs := validateCatalogDuplicates([]*Module{modA}, snapshot)
	if !hasRule(errs, RuleDuplicatePort) {
		t.Errorf("expected %q (alpha and snapshot beta both on 8300), got:\n%s", RuleDuplicatePort, joinErrs(errs))
	}
	if !hasRule(errs, RuleOpenAPIUnknownRequiredModule) {
		t.Errorf("expected %q for x-required-modules [ghost], got:\n%s", RuleOpenAPIUnknownRequiredModule, joinErrs(errs))
	}
}

// TestValidateMigrationsDir: a bare foundation tree gets the layout + ledger
// rules (never the module cross-schema table), and the four real trees pass.
func TestValidateMigrationsDir(t *testing.T) {
	for _, tree := range []string{"registry", "authz", "identity", "org"} {
		if errs := ValidateMigrationsDir(tree, repoPath(t, "migrations", tree)); len(errs) > 0 {
			t.Errorf("migrations/%s must pass:\n%s", tree, joinErrs(errs))
		}
	}

	dir := t.TempDir()
	writeModule(t, dir, map[string]string{
		"0001_roles.sql":  "CREATE ROLE kiban_x; GRANT USAGE ON SCHEMA org TO kiban_x;\n", // foundation trees cross schemas by design
		"0002_tables.sql": "CREATE TABLE platform.x (id int);\n",
	})
	if errs := ValidateMigrationsDir("t", dir); !hasRule(errs, RuleMigrationChecksum) {
		t.Fatalf("expected a missing-ledger error, got:\n%s", joinErrs(errs))
	}
	files, loadErrs := LoadMigrationsDir("t", dir)
	if len(loadErrs) > 0 {
		t.Fatal(loadErrs)
	}
	if err := WriteChecksumLedgerDir(dir, files); err != nil {
		t.Fatal(err)
	}
	if errs := ValidateMigrationsDir("t", dir); len(errs) > 0 {
		t.Fatalf("ledgered tree must pass:\n%s", joinErrs(errs))
	}
	if err := os.Rename(filepath.Join(dir, "0002_tables.sql"), filepath.Join(dir, "0003_tables.sql")); err != nil {
		t.Fatal(err)
	}
	errs := ValidateMigrationsDir("t", dir)
	out := joinErrs(errs)
	if !strings.Contains(out, "0002_tables.sql: recorded") || !strings.Contains(out, "0003_tables.sql: not recorded") {
		t.Fatalf("a renamed shipped migration must fail as both missing and unrecorded, got:\n%s", out)
	}
}

// TestShippedModulesPass proves every shipped module (not only notification) passes the whole
// batch — the same shape `make validate-modules` runs.
func TestShippedModulesPass(t *testing.T) {
	var mods []*Module
	for _, mk := range []string{"notification", "timesheet", "docs", "helpdesk"} {
		mod, loadErrs := LoadModule(repoPath(t, "modules", mk))
		if mod == nil || len(loadErrs) > 0 {
			t.Fatalf("%s: %v", mk, loadErrs)
		}
		mods = append(mods, mod)
	}
	if errs := ValidateBatch(mods, CatalogSnapshot{}); len(errs) > 0 {
		t.Fatalf("shipped modules must pass:\n%s", joinErrs(errs))
	}
}

// TestValidateBatch_DependencyGraph proves unknown-key, cycle, and unsatisfiable-range detection
// against a synthetic batch.
func TestValidateBatch_DependencyGraph(t *testing.T) {
	t.Run("unknown dependency", func(t *testing.T) {
		files := cloneFiles(baselineFiles("gamma"))
		files["module.manifest.json"] = strings.Replace(files["module.manifest.json"],
			`"dependencies": []`, `"dependencies": [{"moduleKey": "ghost", "versionRange": ">=1.0.0 <2.0.0", "required": true}]`, 1)
		dir := t.TempDir()
		writeModule(t, dir, files)
		mod, loadErrs := LoadModule(dir)
		if mod == nil || len(loadErrs) > 0 {
			t.Fatalf("load errors: %v", loadErrs)
		}
		errs := validateDependencyGraph([]*Module{mod}, CatalogSnapshot{})
		if !hasRule(errs, RuleDependencyUnknown) {
			t.Fatalf("expected %q, got:\n%s", RuleDependencyUnknown, joinErrs(errs))
		}
	})

	t.Run("unsatisfiable version range", func(t *testing.T) {
		filesA := cloneFiles(baselineFiles("delta"))
		filesA["module.manifest.json"] = strings.Replace(filesA["module.manifest.json"],
			`"dependencies": []`, `"dependencies": [{"moduleKey": "epsilon", "versionRange": ">=2.0.0 <3.0.0", "required": true}]`, 1)
		dirA := t.TempDir()
		writeModule(t, dirA, filesA)

		filesB := baselineFiles("epsilon") // version 1.0.0 — does not satisfy >=2.0.0
		dirB := t.TempDir()
		writeModule(t, dirB, filesB)

		modA, lA := LoadModule(dirA)
		modB, lB := LoadModule(dirB)
		if modA == nil || modB == nil {
			t.Fatalf("load errors: A=%v B=%v", lA, lB)
		}
		errs := validateDependencyGraph([]*Module{modA, modB}, CatalogSnapshot{})
		if !hasRule(errs, RuleDependencyRange) {
			t.Fatalf("expected %q, got:\n%s", RuleDependencyRange, joinErrs(errs))
		}
	})

	t.Run("dependency cycle", func(t *testing.T) {
		filesA := cloneFiles(baselineFiles("zeta"))
		filesA["module.manifest.json"] = strings.Replace(filesA["module.manifest.json"],
			`"dependencies": []`, `"dependencies": [{"moduleKey": "eta", "versionRange": ">=1.0.0 <2.0.0", "required": true}]`, 1)
		dirA := t.TempDir()
		writeModule(t, dirA, filesA)

		filesB := cloneFiles(baselineFiles("eta"))
		filesB["module.manifest.json"] = strings.Replace(filesB["module.manifest.json"],
			`"dependencies": []`, `"dependencies": [{"moduleKey": "zeta", "versionRange": ">=1.0.0 <2.0.0", "required": true}]`, 1)
		dirB := t.TempDir()
		writeModule(t, dirB, filesB)

		modA, lA := LoadModule(dirA)
		modB, lB := LoadModule(dirB)
		if modA == nil || modB == nil {
			t.Fatalf("load errors: A=%v B=%v", lA, lB)
		}
		errs := validateDependencyGraph([]*Module{modA, modB}, CatalogSnapshot{})
		if !hasRule(errs, RuleDependencyCycle) {
			t.Fatalf("expected %q, got:\n%s", RuleDependencyCycle, joinErrs(errs))
		}
	})
}

// TestValidateModule_FrontendSyntheticAccessKeyExempt proves the one documented exemption to
// "frontend feature keys absent from the authz fragment": the platform-synthesized
// "<moduleKey>.access" key (internal/authz/summary.go) never needs to appear in the module's own
// fragment — this is exactly what notification's real frontend.manifest.json relies on.
func TestValidateModule_FrontendSyntheticAccessKeyExempt(t *testing.T) {
	files := cloneFiles(baselineFiles("theta"))
	files["frontend/frontend.manifest.json"] = strings.Replace(files["frontend/frontend.manifest.json"],
		`"featureKey": "theta.items.manage"`, `"featureKey": "theta.access"`, 1)
	dir := t.TempDir()
	writeModule(t, dir, files)
	mod, loadErrs := LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("load errors: %v", loadErrs)
	}
	if err := WriteChecksumLedger(dir, mod); err != nil {
		t.Fatalf("WriteChecksumLedger: %v", err)
	}
	mod, loadErrs = LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("reload after checksum write: %v", loadErrs)
	}
	errs := ValidateModule(mod)
	if hasRule(errs, RuleFrontendFeatureKeyMissing) {
		t.Fatalf("synthesized <moduleKey>.access key must be exempt from frontend-feature-key-missing; got:\n%s", joinErrs(errs))
	}
}

// TestLoadModule_HeadlessModuleIsFirstClass proves a module with no frontend/ dir at all loads
// and validates cleanly (frontend/ is optional; headless modules are first-class).
func TestLoadModule_HeadlessModuleIsFirstClass(t *testing.T) {
	files := cloneFiles(baselineFiles("iota"))
	delete(files, "frontend/frontend.manifest.json")
	dir := t.TempDir()
	writeModule(t, dir, files)
	mod, loadErrs := LoadModule(dir)
	if mod == nil || len(loadErrs) > 0 {
		t.Fatalf("load errors: %v", loadErrs)
	}
	if mod.Frontend != nil {
		t.Fatalf("expected nil Frontend for a headless module")
	}
	if err := WriteChecksumLedger(dir, mod); err != nil {
		t.Fatalf("WriteChecksumLedger: %v", err)
	}
	errs := mustLoadAndValidate(t, dir)
	if len(errs) > 0 {
		t.Fatalf("headless module must be §8-clean; got:\n%s", joinErrs(errs))
	}
}

// TestLoadModule_MissingRequiredArtifact proves a missing required artifact (
// only module.manifest.json/authz.fragment.json/openapi.yaml/migrations/ are required) is a
// loud load error, not a silently-passing module.
func TestLoadModule_MissingRequiredArtifact(t *testing.T) {
	files := cloneFiles(baselineFiles("kappa"))
	delete(files, "openapi.yaml")
	dir := t.TempDir()
	writeModule(t, dir, files)
	mod, loadErrs := LoadModule(dir)
	if mod == nil {
		t.Fatalf("expected a non-nil module even with a missing optional-load artifact; load errors: %v", loadErrs)
	}
	if len(loadErrs) == 0 {
		t.Fatal("expected a load error for the missing openapi.yaml")
	}
}

func TestDecodeStrict_IgnoresUnderscoreCommentKeys(t *testing.T) {
	data := []byte(`{"_comment": "hello", "moduleKey": "widget", "routeBase": "/app/widget", "routes": [], "navFromFeatures": true, "sdkVersionRange": ">=0.1.0 <1.0.0", "remoteEntryUrl": null}`)
	var fm FrontendManifest
	if err := decodeStrict(data, &fm); err != nil {
		t.Fatalf("decodeStrict with a leading-underscore comment key should not error: %v", err)
	}
	if fm.ModuleKey != "widget" {
		t.Fatalf("expected moduleKey widget, got %q", fm.ModuleKey)
	}
}

func TestLoadCatalogSnapshot_EmptyPathIsNoop(t *testing.T) {
	snap, err := LoadCatalogSnapshot("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.Modules) != 0 {
		t.Fatalf("expected empty snapshot, got %d entries", len(snap.Modules))
	}
}

func TestLoadCatalogSnapshot_MissingFileErrors(t *testing.T) {
	if _, err := LoadCatalogSnapshot(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected an error for a missing catalog snapshot file")
	}
}

// TestValidateBatch_DuplicateRelationsType proves the cross-module half of "one module owns an
// object type" covers the `relations` keys — the types the engine
// actually loads — not only `objects[].objectType`.
func TestValidateBatch_DuplicateRelationsType(t *testing.T) {
	dirA := t.TempDir()
	writeModule(t, dirA, baselineFiles("alpha"))
	dirB := t.TempDir()
	filesB := cloneFiles(baselineFiles("beta"))
	// beta keeps its own objects entry but declares alpha_item in relations.
	filesB["authz.fragment.json"] = strings.Replace(filesB["authz.fragment.json"], `"relations": {
    "beta_item": {`, `"relations": {
    "alpha_item": {`, 1)
	writeModule(t, dirB, filesB)

	modA, lA := LoadModule(dirA)
	modB, lB := LoadModule(dirB)
	if modA == nil || modB == nil {
		t.Fatalf("load errors: A=%v B=%v", lA, lB)
	}
	errs := ValidateBatch([]*Module{modA, modB}, CatalogSnapshot{})
	if !hasRule(errs, RuleDuplicateObjectType) {
		t.Fatalf("expected %q for alpha_item declared in both modules' relations, got:\n%s", RuleDuplicateObjectType, joinErrs(errs))
	}
}
