// SPDX-License-Identifier: Apache-2.0

// The registry's fragment-installation path. Registering/enabling a module also gets its
// authz.fragment.json "relations" section into authz.model_fragment, validated through the SAME
// subset wall (engine.LoadModel) modvalidate/fragment already use, before ever
// writing. active mirrors the module's installed+enabled state (never row deletion — a disabled
// module's fragment stays on record, just inert).
package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// sqlExecutor is the common subset of *pgxpool.Pool and pgx.Tx this file needs — lets
// upsertAuthzFragment/setAuthzFragmentActive run either inside SetEnabled's existing transaction
// or standalone from Seed (which, like the rest of Seed, does its per-module writes outside any
// single wrapping transaction — matching module_catalog/module_installation's own seed style).
type sqlExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// upsertAuthzFragment validates fragment against the supported-subset wall (the same
// engine.LoadModel modvalidate and internal/authz/fragment already run — refusing loudly here,
// BEFORE any write, is cheaper than a bad row silently going inert at Check time) and then
// upserts it into authz.model_fragment. A nil/empty fragment is a no-op (not every module
// declares one).
func upsertAuthzFragment(ctx context.Context, ex sqlExecutor, moduleKey string, fragment []byte, active bool) error {
	if len(fragment) == 0 {
		return nil
	}
	m, err := engine.LoadModel(fragment)
	if err != nil {
		return fmt.Errorf("registry: seed: module %q authz fragment failed the subset wall: %w", moduleKey, err)
	}
	// Same base-type-redeclaration reject modvalidate enforces at build time
	// (internal/modvalidate/fragment.go), asserted again here — this is the actual runtime
	// write gate a fragment passes through before ever reaching authz.model_fragment.
	types := make([]string, 0, len(m))
	for typ := range m {
		if engine.IsBaseType(typ) {
			return fmt.Errorf(
				"registry: seed: module %q authz fragment declares object type %q, which is a platform base type — "+
					"fragments may reference base relations but never redefine a base type", moduleKey, typ)
		}
		types = append(types, typ)
	}
	// One module owns an object type: a fragment declaring a type
	// another module's stored fragment (active or not) already declares is refused before any
	// write — fragment.Load would refuse the pair at every request otherwise.
	var other string
	err = ex.QueryRow(ctx, `SELECT module_key FROM authz.model_fragment WHERE module_key <> $1 AND fragment ?| $2 LIMIT 1`, moduleKey, types).Scan(&other)
	switch {
	case err == nil:
		return fmt.Errorf("registry: seed: module %q authz fragment declares an object type module %q already declares (%v) — one module owns a type", moduleKey, other, types)
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("registry: seed: check model_fragment type ownership for %q: %w", moduleKey, err)
	}
	_, err = ex.Exec(ctx, `
		INSERT INTO authz.model_fragment (module_key, fragment, active, loaded_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (module_key) DO UPDATE
		SET fragment = EXCLUDED.fragment, active = EXCLUDED.active, loaded_at = now()
	`, moduleKey, fragment, active)
	if err != nil {
		return fmt.Errorf("registry: seed: upsert model_fragment %q: %w", moduleKey, err)
	}
	return nil
}

// setAuthzFragmentActive flips an EXISTING model_fragment row's active flag to match a module's
// new enabled state (disable → active=false, re-enable →
// active=true — never a row delete). A module with no fragment row (no authz.fragment.json, or
// never seeded one) is a silent no-op — nothing to flip.
func setAuthzFragmentActive(ctx context.Context, ex sqlExecutor, moduleKey string, active bool) error {
	_, err := ex.Exec(ctx, `
		UPDATE authz.model_fragment SET active = $2, loaded_at = now() WHERE module_key = $1
	`, moduleKey, active)
	if err != nil {
		return fmt.Errorf("registry: set enabled: update model_fragment active %q: %w", moduleKey, err)
	}
	return nil
}
