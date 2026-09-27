// SPDX-License-Identifier: Apache-2.0

package modvalidate

import "fmt"

// Rule names — one per module-contract reject rule this package automates.
// Tests assert on these names directly (the conformance suite).
const (
	RuleUnknownField                       = "unknown-field"
	RuleUnknownContractVersion             = "unknown-contract-version"
	RuleModuleKeyFormat                    = "module-key-format"
	RuleBasePathMismatch                   = "base-path-mismatch"
	RuleSchemaMismatch                     = "schema-mismatch"
	RuleFeaturePrefixMismatch              = "feature-prefix-mismatch"
	RuleRouteBaseMismatch                  = "route-base-mismatch"
	RuleFragmentModuleKeyMismatch          = "fragment-module-key-mismatch"
	RuleAuthzSubsetWall                    = "authz-subset-wall"
	RuleAuthzBaseTypeRedeclared            = "authz-base-type-redeclared"
	RuleAuthzRelationUnknown               = "authz-relation-unknown"
	RuleAuthzAnchorMissing                 = "authz-anchor-missing"
	RuleDependencyUnknown                  = "dependency-unknown"
	RuleDependencyCycle                    = "dependency-cycle"
	RuleDependencyRange                    = "dependency-range"
	RuleDependencyRangeSyntax              = "dependency-range-syntax"
	RuleMigrationFilename                  = "migration-filename"
	RuleMigrationOrder                     = "migration-order"
	RuleMigrationCrossSchema               = "migration-cross-schema"
	RuleMigrationUnsafeStatement           = "migration-unsafe-statement"
	RuleMigrationChecksum                  = "migration-checksum-mismatch"
	RuleScopeTypeInvalid                   = "scope-type-invalid"
	RuleServicePort                        = "service-port"
	RuleHealthPath                         = "health-path"
	RuleDependencyRequired                 = "dependency-required"
	RuleFragmentObjectInvalid              = "fragment-object-invalid"
	RuleFragmentFeatureInvalid             = "fragment-feature-invalid"
	RuleFragmentRoleInvalid                = "fragment-role-invalid"
	RuleFragmentRowScopeInvalid            = "fragment-row-scope-invalid"
	RuleFrontendSDKVersionRange            = "frontend-sdk-version-range"
	RuleOpenAPIUnknownRequiredModule       = "openapi-unknown-required-module"
	RuleDuplicatePort                      = "duplicate-port"
	RuleOpenAPIOperationID                 = "openapi-missing-operation-id"
	RuleOpenAPIPathOutsideBasePath         = "openapi-path-outside-basepath"
	RuleOpenAPIMissingCapabilityAnnotation = "openapi-missing-capability-annotation"
	RuleFrontendDuplicateRouteID           = "frontend-duplicate-route-id"
	RuleFrontendPathCollision              = "frontend-path-collision"
	RuleFrontendBadParamName               = "frontend-bad-param-name"
	RuleFrontendFeatureKeyMissing          = "frontend-feature-key-missing"
	RuleDuplicateModuleKey                 = "duplicate-module-key"
	RuleDuplicateBasePath                  = "duplicate-base-path"
	RuleDuplicateRouteID                   = "duplicate-route-id"
	RuleDuplicateFeatureKey                = "duplicate-feature-key"
	RuleDuplicateObjectType                = "duplicate-object-type"
	RuleVersionFormat                      = "version-format"
	RuleLicenseFileClassMismatch           = "license-file-class-mismatch"
	RuleLicenseSPDXInvalid                 = "license-spdx-invalid"
)

// ValidationError is one named contract rejection. Never a warning.
type ValidationError struct {
	ModuleKey string
	Rule      string
	Message   string
}

func (e ValidationError) Error() string {
	mk := e.ModuleKey
	if mk == "" {
		mk = "(unknown module)"
	}
	return fmt.Sprintf("%s: [%s] %s", mk, e.Rule, e.Message)
}

func errf(moduleKey, rule, format string, args ...any) ValidationError {
	return ValidationError{ModuleKey: moduleKey, Rule: rule, Message: fmt.Sprintf(format, args...)}
}
