// SPDX-License-Identifier: Apache-2.0

// Package modvalidate implements the module-artifact validator required by the module contract.
// It loads a module directory's four artifacts
// (module.manifest.json, authz.fragment.json, openapi.yaml, migrations/, and the optional
// frontend/frontend.manifest.json), validates each individually, and cross-checks a batch of
// modules (plus an optional external catalog snapshot) against the contract's reject list.
//
// Every contract rule that is automatable from the artifacts alone is implemented here (reused code,
// not reimplemented, where the platform already owns the logic — e.g. the authz subset wall is
// enforced via internal/authz/engine.LoadModel, never duplicated). Rules that need
// runtime/deployment state this package cannot see (deployment org-unit taxonomy,
// generated-output staleness) are out of scope here.
package modvalidate

import "encoding/json"

// Manifest mirrors the contract's module.manifest.json shape exactly. Unknown fields are
// rejected at decode time (decodeStrict), except keys prefixed with "_" (author
// comments/annotations — see notification's frontend.manifest.json).
type Manifest struct {
	ContractVersion string               `json:"contractVersion"`
	ModuleKey       string               `json:"moduleKey"`
	DisplayName     string               `json:"displayName"`
	Version         string               `json:"version"`
	ScopeType       string               `json:"scopeType"`
	Mandatory       bool                 `json:"mandatory"`
	Service         ManifestService      `json:"service"`
	Dependencies    []ManifestDependency `json:"dependencies"`
	Org             ManifestOrg          `json:"org"`
	Data            ManifestData         `json:"data"`
	License         ManifestLicense      `json:"license"`
	Events          json.RawMessage      `json:"events"`
}

type ManifestService struct {
	BasePath   string  `json:"basePath"`
	Port       int     `json:"port"`
	HealthPath string  `json:"healthPath"`
	Image      *string `json:"image"`
}

type ManifestDependency struct {
	ModuleKey    string `json:"moduleKey"`
	VersionRange string `json:"versionRange"`
	Required     bool   `json:"required"`
}

type ManifestOrg struct {
	RequiredOrgUnitTypes []string `json:"requiredOrgUnitTypes"`
	UsesMembers          bool     `json:"usesMembers"`
	UsesPositions        bool     `json:"usesPositions"`
}

type ManifestData struct {
	PostgresSchema string `json:"postgresSchema"`
	MigrationsPath string `json:"migrationsPath"`
}

type ManifestLicense struct {
	Class               string `json:"class"`
	SPDX                string `json:"spdx"`
	EntitlementRequired bool   `json:"entitlementRequired"`
}

// AuthzFragment mirrors the contract's authz.fragment.json shape. Relations is kept as raw JSON
// and handed to internal/authz/engine.LoadModel verbatim — the subset wall is enforced there,
// never reimplemented here.
type AuthzFragment struct {
	ModuleKey       string                  `json:"moduleKey"`
	Roles           []FragmentRole          `json:"roles"`
	Objects         []FragmentObject        `json:"objects"`
	Relations       json.RawMessage         `json:"relations"`
	Features        []FragmentFeature       `json:"features"`
	FieldCatalog    []map[string]any        `json:"fieldCatalog"`
	FieldSets       []map[string]any        `json:"fieldSets"`
	RowScopes       []FragmentRowScope      `json:"rowScopes"`
	BootstrapPolicy FragmentBootstrapPolicy `json:"bootstrapPolicy"`
}

type FragmentRole struct {
	RoleKey                string `json:"roleKey"`
	Label                  string `json:"label"`
	ScopeType              string `json:"scopeType"`
	GrantsShellAccess      bool   `json:"grantsShellAccess"`
	SeedCompanyCreatorRole bool   `json:"seedCompanyCreatorRole"`
	SortOrder              int    `json:"sortOrder"`
}

type FragmentObject struct {
	ObjectType         string   `json:"objectType"`
	Label              string   `json:"label"`
	ScopeKind          string   `json:"scopeKind"`
	ParentKind         string   `json:"parentKind"`
	ManagerRelation    string   `json:"managerRelation"`
	GrantableRelations []string `json:"grantableRelations"`
	ShowInPermissionUi bool     `json:"showInPermissionUi"`
	SortOrder          int      `json:"sortOrder"`
}

type FragmentFeature struct {
	FeatureKey        string         `json:"featureKey"`
	Label             string         `json:"label"`
	ScopeType         string         `json:"scopeType"`
	RequiresCompany   bool           `json:"requiresCompany"`
	AccessRuleKind    string         `json:"accessRuleKind"`
	AccessRulePayload map[string]any `json:"accessRulePayload"`
	SortOrder         int            `json:"sortOrder"`
	IsSidebarEntry    bool           `json:"isSidebarEntry"`
}

type FragmentRowScope struct {
	EntityType string   `json:"entityType"`
	Rules      []string `json:"rules"`
}

type FragmentBootstrapPolicy struct {
	SeedCompanyCreatorObjectRelations []any `json:"seedCompanyCreatorObjectRelations"`
}

// FrontendManifest mirrors the contract's frontend.manifest.json shape.
type FrontendManifest struct {
	ModuleKey       string          `json:"moduleKey"`
	RouteBase       string          `json:"routeBase"`
	Routes          []FrontendRoute `json:"routes"`
	NavFromFeatures bool            `json:"navFromFeatures"`
	SdkVersionRange string          `json:"sdkVersionRange"`
	RemoteEntryUrl  *string         `json:"remoteEntryUrl"`
}

type FrontendRoute struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	FeatureKey string `json:"featureKey"`
}

// MigrationFile is one loaded migrations/NNNN_description.sql file.
type MigrationFile struct {
	Name     string // basename, e.g. "0001_schema.sql"
	Contents []byte
	Checksum string // sha256 hex of Contents
}

// Module is a fully loaded module directory: the four required artifacts plus the optional
// frontend one.
type Module struct {
	Dir        string
	ModuleKey  string // taken from the manifest once loaded; "" if the manifest itself failed
	Manifest   *Manifest
	Fragment   *AuthzFragment
	OpenAPI    map[string]any // parsed YAML document, generic (openapi.yaml is standard OpenAPI, not a custom contract shape)
	OpenAPIRaw []byte
	Migrations []MigrationFile
	Frontend   *FrontendManifest // nil when the module has no frontend/ dir (headless modules are first-class)
}

// CatalogEntry is the minimal external-catalog-snapshot shape used for cross-module duplicate
// and dependency-resolution checks against modules NOT in the current validate batch (duplicates
// are rejected across the whole catalog). No registry export mechanism exists yet, so this
// snapshot is supplied as a JSON file (-catalog flag) or built in-memory in tests.
type CatalogEntry struct {
	ModuleKey   string   `json:"moduleKey"`
	Version     string   `json:"version"`
	BasePath    string   `json:"basePath"`
	Port        int      `json:"port,omitempty"`
	RouteBase   string   `json:"routeBase,omitempty"`
	RouteIDs    []string `json:"routeIds,omitempty"`
	FeatureKeys []string `json:"featureKeys,omitempty"`
	ObjectTypes []string `json:"objectTypes,omitempty"`
}

// CatalogSnapshot is a set of CatalogEntry rows representing modules already known to the
// platform, outside the batch being validated right now.
type CatalogSnapshot struct {
	Modules []CatalogEntry `json:"modules"`
}
