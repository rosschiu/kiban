// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// AppManifest is what an app registers at runtime: an OpenFGA-style model registration plus
// the identity of the backend allowed to write tuples on it. The app serves itself beside
// Kiban; nothing here names an upstream.
type AppManifest struct {
	Key             string          `json:"key"`
	DisplayName     string          `json:"displayName"`
	Version         string          `json:"version"`
	ServiceClientID string          `json:"serviceClientId"`
	Features        []string        `json:"features"`
	AuthzFragment   json.RawMessage `json:"authzFragment"` // the fragment's "relations" section
}

var (
	serviceClientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	featureKeyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// ErrInvalidManifest carries a caller-fixable validation failure (422).
type ErrInvalidManifest struct{ Field, Msg string }

func (e *ErrInvalidManifest) Error() string {
	return "registry: app manifest: " + e.Field + ": " + e.Msg
}

func (m AppManifest) validate() error {
	switch {
	case !moduleKeyPattern.MatchString(m.Key):
		return &ErrInvalidManifest{"key", "must match ^[a-z][a-z0-9_]{1,31}$"}
	case m.DisplayName == "":
		return &ErrInvalidManifest{"displayName", "required"}
	case m.Version == "":
		return &ErrInvalidManifest{"version", "required"}
	case !serviceClientIDPattern.MatchString(m.ServiceClientID):
		return &ErrInvalidManifest{"serviceClientId", "must match ^[a-z][a-z0-9_-]{1,63}$"}
	case len(m.AuthzFragment) == 0:
		return &ErrInvalidManifest{"authzFragment", "required"}
	}
	for _, f := range m.Features {
		if !featureKeyPattern.MatchString(f) || f[:len(m.Key)+1] != m.Key+"." {
			return &ErrInvalidManifest{"features", "each feature key must be <key>.<name>, got " + f}
		}
	}
	return nil
}

// RegisterApp upserts the app into the catalog (installed, enabled state untouched on re-register)
// and its registration row, then loads its fragment through the same subset wall the sample
// modules pass. auditRecord runs inside the transaction.
func (s *Store) RegisterApp(ctx context.Context, m AppManifest, actor string, auditRecord func(context.Context, pgx.Tx) error) error {
	if err := m.validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("registry: register app: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	q := New(tx)
	if err := q.UpsertModuleCatalog(ctx, UpsertModuleCatalogParams{
		ModuleKey: m.Key, DisplayName: m.DisplayName, ScopeType: "company", Mandatory: false,
		BasePath: "/api/" + m.Key, HealthPath: "/health", Port: 0, LicenseClass: "open",
		ManifestVersion: m.Version, IsActive: true,
	}); err != nil {
		return fmt.Errorf("registry: register app: catalog: %w", err)
	}
	if _, err := q.SeedModuleInstallationMissing(ctx, SeedModuleInstallationMissingParams{
		ModuleKey: m.Key, Installed: true, Enabled: false, Version: &m.Version,
	}); err != nil {
		return fmt.Errorf("registry: register app: installation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE platform.module_installation SET installed = true, version = $2 WHERE module_key = $1`, m.Key, m.Version); err != nil {
		return fmt.Errorf("registry: register app: installation version: %w", err)
	}
	if err := setCatalogFeatures(ctx, tx, m.Key, m.Features); err != nil {
		return fmt.Errorf("registry: register app: features: %w", err)
	}
	manifestJSON, _ := json.Marshal(m)
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.app_registration (module_key, service_client_id, manifest, registered_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (module_key) DO UPDATE SET service_client_id = EXCLUDED.service_client_id,
			manifest = EXCLUDED.manifest, registered_by = EXCLUDED.registered_by, registered_at = now()`,
		m.Key, m.ServiceClientID, manifestJSON, actor); err != nil {
		return fmt.Errorf("registry: register app: registration: %w", err)
	}
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM platform.module_installation WHERE module_key = $1`, m.Key).Scan(&enabled); err != nil {
		return fmt.Errorf("registry: register app: read enabled: %w", err)
	}
	if err := upsertAuthzFragment(ctx, tx, m.Key, m.AuthzFragment, enabled); err != nil {
		return &ErrInvalidManifest{"authzFragment", err.Error()}
	}
	if auditRecord != nil {
		if err := auditRecord(ctx, tx); err != nil {
			return fmt.Errorf("registry: register app: audit: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// setCatalogFeatures stores the module's declared feature keys on its catalog row.
func setCatalogFeatures(ctx context.Context, ex sqlExecutor, moduleKey string, features []string) error {
	if features == nil {
		features = []string{}
	}
	_, err := ex.Exec(ctx, `UPDATE platform.module_catalog SET features = $2 WHERE module_key = $1`, moduleKey, features)
	return err
}

// catalogFeatures maps module_key -> declared feature keys for the whole catalog.
func (s *Store) catalogFeatures(ctx context.Context) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT module_key, features FROM platform.module_catalog`)
	if err != nil {
		return nil, fmt.Errorf("registry: list catalog features: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var k string
		var f []string
		if err := rows.Scan(&k, &f); err != nil {
			return nil, err
		}
		if f == nil {
			f = []string{}
		}
		out[k] = f
	}
	return out, rows.Err()
}

// appRegistrations maps module_key -> service_client_id for every registered app.
func (s *Store) appRegistrations(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT module_key, service_client_id FROM platform.app_registration`)
	if err != nil {
		return nil, fmt.Errorf("registry: list app registrations: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, c string
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// IsInvalidManifest reports whether err is a caller-fixable manifest error.
func IsInvalidManifest(err error) bool {
	var e *ErrInvalidManifest
	return errors.As(err, &e)
}
