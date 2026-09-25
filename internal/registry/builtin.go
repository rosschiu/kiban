// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	docsartifacts "github.com/rosschiu/kiban/modules/docs"
	helpdeskartifacts "github.com/rosschiu/kiban/modules/helpdesk"
	notificationartifacts "github.com/rosschiu/kiban/modules/notification"
	timesheetartifacts "github.com/rosschiu/kiban/modules/timesheet"
)

// authzRelationsSection extracts just the "relations" key from a module's full
// authz.fragment.json — the shape authz.model_fragment.fragment / internal/authz/fragment.Row
// store (the engine-model-fragment subset, not the whole artifact file).
func authzRelationsSection(fullFragment []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(fullFragment, &raw); err != nil {
		return nil, fmt.Errorf("parse authz.fragment.json: %w", err)
	}
	// A module whose ENTIRE access-tier surface references the platform base model's own
	// relations (company_module#admin/#submitter/#approver) legitimately declares NO relations
	// of its own — timesheet is one such module (see modules/timesheet/authz.fragment.json's
	// own _comment). A genuinely absent "relations" key is that case, not an
	// authoring mistake: return nil (registry.upsertAuthzFragment already treats a nil/empty
	// fragment as a documented no-op — "not every module declares one" — so this changes nothing
	// about what gets installed for a module that DOES declare one, like notification).
	relations, ok := raw["relations"]
	if !ok {
		return nil, nil
	}
	return relations, nil
}

// BuiltinModules is the known-manifest set Seed validates KIBAN_INSTALLED_MODULES against.
// This literal Go list IS the install path: no generic manifest-file ingestion mechanism exists
// yet, so a module developer hand-adds an entry mirroring their own module.manifest.json's
// service/data/license fields.
var BuiltinModules = []ModuleManifest{
	{
		ModuleKey:            "notification",
		DisplayName:          "Notification",
		ScopeType:            "company",
		Mandatory:            false,
		BasePath:             "/api/notification",
		HealthPath:           "/health",
		Port:                 8150,
		LicenseClass:         "foundation",
		ManifestVersion:      mustManifest(notificationartifacts.ManifestJSON).Version,
		RequiredOrgUnitTypes: mustManifest(notificationartifacts.ManifestJSON).Org.RequiredOrgUnitTypes,
		AuthzFragment:        notificationAuthzRelations,
	},
	{
		ModuleKey:            "timesheet",
		DisplayName:          "Timesheet",
		ScopeType:            "company",
		Mandatory:            false,
		BasePath:             "/api/timesheet",
		HealthPath:           "/health",
		Port:                 8160,
		LicenseClass:         "foundation",
		ManifestVersion:      mustManifest(timesheetartifacts.ManifestJSON).Version,
		RequiredOrgUnitTypes: mustManifest(timesheetartifacts.ManifestJSON).Org.RequiredOrgUnitTypes,
		AuthzFragment:        timesheetAuthzRelations,
	},
	{
		ModuleKey:            "docs",
		DisplayName:          "Docs",
		ScopeType:            "company",
		Mandatory:            false,
		BasePath:             "/api/docs",
		HealthPath:           "/health",
		Port:                 8170,
		LicenseClass:         "foundation",
		ManifestVersion:      mustManifest(docsartifacts.ManifestJSON).Version,
		RequiredOrgUnitTypes: mustManifest(docsartifacts.ManifestJSON).Org.RequiredOrgUnitTypes,
		AuthzFragment:        docsAuthzRelations,
	},
	{
		ModuleKey:            "helpdesk",
		DisplayName:          "Helpdesk",
		ScopeType:            "company",
		Mandatory:            false,
		BasePath:             "/api/helpdesk",
		HealthPath:           "/health",
		Port:                 8180,
		LicenseClass:         "foundation",
		ManifestVersion:      mustManifest(helpdeskartifacts.ManifestJSON).Version,
		RequiredOrgUnitTypes: mustManifest(helpdeskartifacts.ManifestJSON).Org.RequiredOrgUnitTypes,
		AuthzFragment:        helpdeskAuthzRelations,
	},
}

// notificationAuthzRelations is notification's authz.fragment.json "relations" section,
// extracted once at process startup. A malformed embedded fragment is a build-time
// invariant violation — refuse loudly (panic, same "never silently drop a bad fragment" posture
// the fragment-installer itself takes at Seed time) rather than start with a module whose
// fragment silently never installs.
var notificationAuthzRelations = mustAuthzRelations(notificationartifacts.AuthzFragmentJSON)

// timesheetAuthzRelations is timesheet's own extraction — nil, since its fragment
// declares no "relations" key of its own (every access tier it needs already
// exists on the platform base model, referenced only — see modules/timesheet/authz.fragment.
// json's own _comment). authzRelationsSection returns nil for a genuinely absent key rather than
// erroring; registry.upsertAuthzFragment already treats a nil fragment as a documented no-op.
var timesheetAuthzRelations = mustAuthzRelations(timesheetartifacts.AuthzFragmentJSON)

// docsAuthzRelations is docs's own extraction — declares one object type
// (docs_document) with owner/editor/viewer, the module's fine-grained-sharing showcase (see
// modules/docs/authz.fragment.json's own _comment).
var docsAuthzRelations = mustAuthzRelations(docsartifacts.AuthzFragmentJSON)

// helpdeskAuthzRelations is helpdesk's own extraction — nil, since its fragment declares
// no "relations" key of its own (every access tier it needs already exists
// on the platform base model, referenced only — the OTHER authz idiom from docs, contrasted
// deliberately; see modules/helpdesk/authz.fragment.json's own _comment).
var helpdeskAuthzRelations = mustAuthzRelations(helpdeskartifacts.AuthzFragmentJSON)

func mustAuthzRelations(fullFragment []byte) []byte {
	relations, err := authzRelationsSection(fullFragment)
	if err != nil {
		panic(fmt.Sprintf("registry: BuiltinModules: %v", err))
	}
	return relations
}

// embeddedManifest is the slice of module.manifest.json BuiltinModules reads from the embedded
// artifact (artifacts.go) so the catalog/installation rows stay in lock-step with the shipped
// manifest.
type embeddedManifest struct {
	Version string `json:"version"`
	Org     struct {
		RequiredOrgUnitTypes []string `json:"requiredOrgUnitTypes"`
	} `json:"org"`
}

// mustManifest parses the embedded module.manifest.json — a malformed/missing embedded manifest
// is a build-time invariant violation, same "refuse loudly" posture as mustAuthzRelations above.
func mustManifest(manifestJSON []byte) embeddedManifest {
	var m embeddedManifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		panic(fmt.Sprintf("registry: BuiltinModules: parse module.manifest.json: %v", err))
	}
	if m.Version == "" {
		panic("registry: BuiltinModules: module.manifest.json has no \"version\" field")
	}
	return m
}

// SeedBuiltin seeds every built-in module as installed, the way a registry booted with all of
// them in KIBAN_INSTALLED_MODULES does. Test fixtures that truncate the catalog call it so a
// shared stack stays usable afterwards.
func SeedBuiltin(ctx context.Context, pool *pgxpool.Pool) error {
	installed := make(map[string]bool, len(BuiltinModules))
	for _, m := range BuiltinModules {
		installed[m.ModuleKey] = true
	}
	return NewStore(pool).Seed(ctx, BuiltinModules, installed)
}
