// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRegisterApp(t *testing.T) {
	ctx := context.Background()
	admin := adminPool(t)
	store := NewStore(registryPool(t))
	const key = "apptest"
	cleanup := func() {
		_, _ = admin.Exec(ctx, `DELETE FROM platform.app_registration WHERE module_key = $1`, key)
		_, _ = admin.Exec(ctx, `DELETE FROM platform.module_installation WHERE module_key = $1`, key)
		_, _ = admin.Exec(ctx, `DELETE FROM platform.module_catalog WHERE module_key = $1`, key)
		_, _ = admin.Exec(ctx, `DELETE FROM authz.model_fragment WHERE module_key = $1`, key)
	}
	cleanup()
	t.Cleanup(cleanup)

	manifest := AppManifest{
		Key: key, DisplayName: "App Test", Version: "1.0.0", ServiceClientID: "apptest-backend",
		Features:      []string{"apptest.ticket.view"},
		AuthzFragment: json.RawMessage(`{"apptest_ticket": {"company_module": {"this": true}, "viewer": {"this": true}}}`),
	}
	audited := 0
	if err := store.RegisterApp(ctx, manifest, "test-actor", func(context.Context, pgx.Tx) error { audited++; return nil }); err != nil {
		t.Fatalf("RegisterApp: %v", err)
	}
	if audited != 1 {
		t.Errorf("audit callback ran %d times, want 1", audited)
	}

	entries, err := store.Catalog(ctx)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var found *CatalogEntry
	for i := range entries {
		if entries[i].ModuleKey == key {
			found = &entries[i]
		}
	}
	if found == nil || !found.External || found.ServiceClientID != "apptest-backend" || !found.Installed || found.Enabled {
		t.Fatalf("catalog entry = %+v, want external, installed, not enabled, client apptest-backend", found)
	}
	capability, code, err := store.Capability(ctx, key)
	if err != nil || capability.ServiceClientID != "apptest-backend" || !capability.External || code == "" {
		t.Fatalf("Capability = %+v code=%q err=%v", capability, code, err)
	}
	if len(capability.Features) != 1 || capability.Features[0] != "apptest.ticket.view" || len(found.Features) != 1 {
		t.Fatalf("features: capability=%v catalog=%v, want [apptest.ticket.view]", capability.Features, found.Features)
	}
	var active bool
	if err := admin.QueryRow(ctx, `SELECT active FROM authz.model_fragment WHERE module_key = $1`, key).Scan(&active); err != nil || active {
		t.Fatalf("fragment row: active=%v err=%v, want stored inactive (not enabled yet)", active, err)
	}

	// Re-register with a new version: idempotent, version bumped, client id replaced.
	manifest.Version, manifest.ServiceClientID = "1.1.0", "apptest-backend-2"
	if err := store.RegisterApp(ctx, manifest, "test-actor", nil); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	var version, client string
	if err := admin.QueryRow(ctx, `SELECT i.version, a.service_client_id FROM platform.module_installation i JOIN platform.app_registration a USING (module_key) WHERE module_key = $1`, key).Scan(&version, &client); err != nil || version != "1.1.0" || client != "apptest-backend-2" {
		t.Fatalf("after re-register: version=%q client=%q err=%v", version, client, err)
	}

	for name, bad := range map[string]AppManifest{
		"bad key":          {Key: "Bad Key", DisplayName: "x", Version: "1", ServiceClientID: "c", AuthzFragment: manifest.AuthzFragment},
		"bad client":       {Key: key, DisplayName: "x", Version: "1", ServiceClientID: "Not Valid", AuthzFragment: manifest.AuthzFragment},
		"foreign feature":  {Key: key, DisplayName: "x", Version: "1", ServiceClientID: "c", Features: []string{"other.thing"}, AuthzFragment: manifest.AuthzFragment},
		"missing fragment": {Key: key, DisplayName: "x", Version: "1", ServiceClientID: "c"},
		"base type":        {Key: key, DisplayName: "x", Version: "1", ServiceClientID: "c", AuthzFragment: json.RawMessage(`{"company": {"admin": {"this": true}}}`)},
	} {
		if err := store.RegisterApp(ctx, bad, "test-actor", nil); !IsInvalidManifest(err) {
			t.Errorf("%s: err = %v, want ErrInvalidManifest", name, err)
		}
	}
}
