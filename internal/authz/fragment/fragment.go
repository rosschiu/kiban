// SPDX-License-Identifier: Apache-2.0

// Package fragment loads module authz fragments (a module's authz.fragment.json "relations" JSON) into
// the effective engine.Model, subset-walled and inert for modules the registry doesn't
// know about or has disabled: an unknown/disabled module's fragment contributes NOTHING to the
// effective model, and — the property this package exists to prove — a check against an
// object type that belongs ONLY to such a fragment answers false, never errors, never allows.
package fragment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// Row is one authz.model_fragment row.
type Row struct {
	ModuleKey string
	Fragment  []byte // raw fragment JSON, authz.fragment.json "relations" shape
	Active    bool
}

// FetchRows reads every stored fragment (active and inactive alike — inactive rows stay on
// record for audit/debugging; only Load decides what's effective).
func FetchRows(ctx context.Context, pool *pgxpool.Pool) ([]Row, error) {
	rows, err := pool.Query(ctx, `SELECT module_key, fragment, active FROM authz.model_fragment`)
	if err != nil {
		return nil, fmt.Errorf("query model_fragment: %w", err)
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.ModuleKey, &r.Fragment, &r.Active); err != nil {
			return nil, fmt.Errorf("scan model_fragment row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Loaded is the result of loading the currently-effective model: the merged Model (types from
// active, registry-known fragments only, subset-validated) plus AllowedTypes — every object
// type ANY known fragment (active or not) declares, used to distinguish "genuinely unknown
// type" (a real error) from "known to a module whose fragment isn't currently effective"
// (inert: false, never an error).
type Loaded struct {
	Model        engine.Model
	AllowedTypes map[string]bool
	// TypeOwner maps every object type an ENABLED fragment declares to its module key — the
	// grants endpoint resolves a tuple's module (and therefore its company_module anchor) from
	// it. Base types and disabled modules' types are absent.
	TypeOwner map[string]string
	// KnownEnabled is the registry's module_key -> enabled map Load was given (presence =
	// catalog knows the module).
	KnownEnabled map[string]bool
}

// Load builds the effective model from the platform base model (engine.BaseModel — always
// loaded, unconditionally, never gated by module state) plus stored fragments, restricted to
// modules the registry currently reports as known+enabled (knownEnabled). Fragments for unknown
// or disabled modules are skipped entirely when merging Model, but their declared object types
// still populate AllowedTypes (from a best-effort unvalidated parse) so Check can answer false
// instead of erroring for them — see Check. Base types are always in AllowedTypes
// too (they are always effective, never subject to the inert-false branch).
//
// A fragment that declares/redefines a base type (company/company_module/module/system/...) is
// refused loudly (fail-closed): this mirrors the same subset-wall reject modvalidate already
// enforces at module-install time (validateFragment) — asserted again here because Load is the
// one place that actually MERGES the base model with fragments, so it is the last line of
// defense against a base type being silently shadowed.
func Load(ctx context.Context, pool *pgxpool.Pool, knownEnabled map[string]bool) (Loaded, error) {
	rows, err := FetchRows(ctx, pool)
	if err != nil {
		return Loaded{}, err
	}

	merged := engine.BaseModel
	allowed := map[string]bool{}
	owner := map[string]string{}
	for t := range engine.BaseModel {
		allowed[t] = true
	}

	for _, r := range rows {
		// Best-effort type-name harvesting for AllowedTypes, independent of subset validation
		// (a fragment's types are "known to exist" even if its module is currently inert).
		if types, err := harvestTypeNames(r.Fragment); err == nil {
			for _, t := range types {
				allowed[t] = true
			}
		}

		if !knownEnabled[r.ModuleKey] || !r.Active {
			continue // an unknown or disabled module's fragment is inert.
		}

		m, err := engine.LoadModel(r.Fragment)
		if err != nil {
			return Loaded{}, fmt.Errorf("module %q: subset-wall/validation failed: %w", r.ModuleKey, err)
		}
		for t := range m {
			if engine.IsBaseType(t) {
				return Loaded{}, fmt.Errorf(
					"module %q: fragment declares object type %q, which is a platform base type — "+
						"fragments may reference base relations but never redefine a base type", r.ModuleKey, t)
			}
			if prev, dup := owner[t]; dup {
				return Loaded{}, fmt.Errorf("module %q: fragment declares object type %q, which module %q already declares — one module owns a type", r.ModuleKey, t, prev)
			}
			owner[t] = r.ModuleKey
		}
		// Same rule modvalidate enforces at install: every declared type carries the
		// company_module anchor the decision layer binds object checks through.
		if err := m.ValidateCompanyModuleAnchor(); err != nil {
			return Loaded{}, fmt.Errorf("module %q: %w", r.ModuleKey, err)
		}
		if merged, err = merged.Merge(m); err != nil {
			return Loaded{}, fmt.Errorf("module %q: %w", r.ModuleKey, err)
		}
	}
	if err := merged.ValidateTupleToUsersetTargets(); err != nil {
		return Loaded{}, fmt.Errorf("effective model: %w", err)
	}

	return Loaded{Model: merged, AllowedTypes: allowed, TypeOwner: owner, KnownEnabled: knownEnabled}, nil
}

// harvestTypeNames parses just the top-level object-type keys of a fragment JSON document,
// without running the subset wall — used only to populate AllowedTypes (a type name is a type
// name whether or not its module is currently enabled).
func harvestTypeNames(fragment []byte) ([]string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(fragment, &raw); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	return names, nil
}
