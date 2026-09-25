// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ModuleManifest is the minimal catalog metadata Seed needs for one module. It stands in for
// the module.manifest.json fields of a real module package; there is no module registration
// workflow yet, so callers (cmd/registry/main.go) supply a built-in list — the KIBAN_INSTALLED_MODULES env
// manifest only says WHICH of these known modules are installed, never their metadata.
type ModuleManifest struct {
	ModuleKey       string
	DisplayName     string
	ScopeType       string // "global" | "company"
	Mandatory       bool
	BasePath        string
	HealthPath      string
	Port            int32
	LicenseClass    string // "foundation" | "open" | "commercial"
	ManifestVersion string

	// AuthzFragment is the module's authz.fragment.json "relations" section (the same shape
	// internal/authz/fragment.Row.Fragment/authz.model_fragment.fragment store),
	// or nil/empty for a module that declares no authz fragment. Seed installs this
	// into authz.model_fragment (subset-wall-validated) alongside the catalog/installation rows
	// it already owns.
	AuthzFragment []byte

	// RequiredOrgUnitTypes is module.manifest.json's org.requiredOrgUnitTypes: install fails
	// (Seed refuses) when the deployment taxonomy (org.org_unit_type) lacks one (module-contract
	// §8, install-time).
	RequiredOrgUnitTypes []string
}

var moduleKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// validateKnownManifests is the install-time half of module-contract §8's structural rules
// (the runtime loader alone would enforce only the moduleKey regex): key
// format, basePath = /api/<key>, port range, healthPath shape, and uniqueness of key / basePath
// / port across the known set. Pure — no DB.
func validateKnownManifests(known []ModuleManifest) error {
	seen := map[string]string{} // "kind:value" -> module key
	for _, m := range known {
		if !moduleKeyPattern.MatchString(m.ModuleKey) {
			return fmt.Errorf("registry: seed: invalid module key %q", m.ModuleKey)
		}
		if m.BasePath != "/api/"+m.ModuleKey {
			return fmt.Errorf("registry: seed: module %q basePath %q must be %q", m.ModuleKey, m.BasePath, "/api/"+m.ModuleKey)
		}
		if m.Port < 1 || m.Port > 65535 {
			return fmt.Errorf("registry: seed: module %q port %d must be in 1..65535", m.ModuleKey, m.Port)
		}
		if !strings.HasPrefix(m.HealthPath, "/") {
			return fmt.Errorf("registry: seed: module %q healthPath %q must be an absolute path", m.ModuleKey, m.HealthPath)
		}
		for _, kv := range []string{"key:" + m.ModuleKey, "basePath:" + m.BasePath, fmt.Sprintf("port:%d", m.Port)} {
			if other, dup := seen[kv]; dup {
				return fmt.Errorf("registry: seed: modules %q and %q both claim %s", other, m.ModuleKey, kv)
			}
			seen[kv] = m.ModuleKey
		}
	}
	return nil
}

// checkOrgUnitTaxonomy refuses any known module whose org.requiredOrgUnitTypes names a type
// absent from org.org_unit_type (seeded by migrations/org/0002; kiban_registry reads it under
// migrations/org/0008's grant).
func (s *Store) checkOrgUnitTaxonomy(ctx context.Context, known []ModuleManifest) error {
	want := map[string]bool{}
	for _, m := range known {
		for _, t := range m.RequiredOrgUnitTypes {
			want[t] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	keys := make([]string, 0, len(want))
	for t := range want {
		keys = append(keys, t)
	}
	rows, err := s.pool.Query(ctx, `SELECT key FROM org.org_unit_type WHERE key = ANY($1)`, keys)
	if err != nil {
		return fmt.Errorf("registry: seed: read org unit taxonomy: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return fmt.Errorf("registry: seed: read org unit taxonomy: %w", err)
		}
		delete(want, k)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("registry: seed: read org unit taxonomy: %w", err)
	}
	for _, m := range known {
		for _, t := range m.RequiredOrgUnitTypes {
			if want[t] {
				return fmt.Errorf("registry: seed: module %q requires org unit type %q, which the deployment taxonomy (org.org_unit_type) does not define", m.ModuleKey, t)
			}
		}
	}
	return nil
}

// ParseInstalledModules parses the KIBAN_INSTALLED_MODULES CSV against the known manifest set,
// unions in every mandatory module, and returns the resulting installed-key set. An unknown
// module key in the CSV is a loud startup failure — never silently dropped.
func ParseInstalledModules(csv string, known []ModuleManifest) (map[string]bool, error) {
	knownKeys := make(map[string]ModuleManifest, len(known))
	for _, m := range known {
		knownKeys[m.ModuleKey] = m
	}

	installed := make(map[string]bool)
	var unknown []string

	csv = strings.TrimSpace(csv)
	if csv != "" {
		for _, raw := range strings.Split(csv, ",") {
			key := strings.TrimSpace(raw)
			if key == "" {
				continue
			}
			if _, ok := knownKeys[key]; !ok {
				unknown = append(unknown, key)
				continue
			}
			installed[key] = true
		}
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf(
			"registry: KIBAN_INSTALLED_MODULES names unknown module key(s): %s",
			strings.Join(unknown, ", "),
		)
	}

	for _, m := range known {
		if m.Mandatory {
			installed[m.ModuleKey] = true
		}
	}

	return installed, nil
}

// Seed applies the manifest to the catalog and seeds installation rows. Catalog metadata is
// manifest-owned and synced on every boot (safe to overwrite). Installation rows are
// seed-MISSING-ONLY: an existing row's installed/enabled is never touched, and
// concurrent seeds (multi-replica boot) race-free via ON CONFLICT DO NOTHING.
func (s *Store) Seed(ctx context.Context, known []ModuleManifest, installedKeys map[string]bool) error {
	if err := validateKnownManifests(known); err != nil {
		return err
	}
	if err := s.checkOrgUnitTaxonomy(ctx, known); err != nil {
		return err
	}
	q := New(s.pool)

	fragmentKeys := make([]string, 0, len(known))
	for _, m := range known {
		if err := q.UpsertModuleCatalog(ctx, UpsertModuleCatalogParams{
			ModuleKey:       m.ModuleKey,
			DisplayName:     m.DisplayName,
			ScopeType:       m.ScopeType,
			Mandatory:       m.Mandatory,
			BasePath:        m.BasePath,
			HealthPath:      m.HealthPath,
			Port:            m.Port,
			LicenseClass:    m.LicenseClass,
			ManifestVersion: m.ManifestVersion,
			IsActive:        true,
		}); err != nil {
			return fmt.Errorf("registry: seed: upsert catalog %s: %w", m.ModuleKey, err)
		}

		if _, err := q.SeedModuleInstallationMissing(ctx, SeedModuleInstallationMissingParams{
			ModuleKey: m.ModuleKey,
			Installed: installedKeys[m.ModuleKey],
			Enabled:   installedKeys[m.ModuleKey],
			Version:   &m.ManifestVersion,
		}); err != nil {
			return fmt.Errorf("registry: seed: installation %s: %w", m.ModuleKey, err)
		}

		if len(m.AuthzFragment) > 0 {
			fragmentKeys = append(fragmentKeys, m.ModuleKey)
		}
	}

	if len(known) == 0 {
		return nil
	}

	// Read back each known module's ACTUAL current enabled state from module_installation (never
	// installedKeys directly: the seed-missing-only rule means a re-seed's installedKeys can be
	// stale against a module an admin has since enabled/disabled via SetEnabled) — used both for
	// the fragment-active mirror and for the default module-access grant (every installed+enabled
	// module, not only fragment-carrying ones).
	allKeys := make([]string, len(known))
	for i, m := range known {
		allKeys[i] = m.ModuleKey
	}
	statusRows, err := q.ListInstallationStatusForKeys(ctx, allKeys)
	if err != nil {
		return fmt.Errorf("registry: seed: load installation status: %w", err)
	}
	enabled := make(map[string]bool, len(statusRows))
	for _, r := range statusRows {
		enabled[r.ModuleKey] = r.Installed && r.Enabled
	}

	for _, moduleKey := range fragmentKeys {
		var fragment []byte
		for _, m := range known {
			if m.ModuleKey == moduleKey {
				fragment = m.AuthzFragment
				break
			}
		}
		if err := upsertAuthzFragment(ctx, s.pool, moduleKey, fragment, enabled[moduleKey]); err != nil {
			return err
		}
	}

	for _, m := range known {
		if !enabled[m.ModuleKey] {
			continue
		}
		if err := defaultGrantModuleForAllActiveCompanies(ctx, s.pool, m.ModuleKey); err != nil {
			return fmt.Errorf("registry: seed: default module-access grant %s: %w", m.ModuleKey, err)
		}
	}

	return nil
}
