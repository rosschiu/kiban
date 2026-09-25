// SPDX-License-Identifier: Apache-2.0

package engine

import _ "embed"

// modelJSON embeds the SAME model.json this package's own tests load from disk
// (model_test.go: os.ReadFile("model.json")), so the platform base authz model is reachable at
// runtime. BaseModel is that model, parsed and validated once at package init via the same
// LoadModel every fragment goes through — a malformed model.json is a build-breaking panic, not
// a runtime surprise (it is committed, reviewed source, never request-shaped input).
//
//go:embed model.json
var modelJSON []byte

// BaseModel is the platform base authz model (company/company_module/module/system and every
// other type model.json defines), always loaded — see internal/authz/fragment.Load, which starts
// every effective-model build from BaseModel and merges active module fragments on top, never
// the reverse (module fragments may reference base relations; they may never redefine a base
// type — fragment.go's Load enforces this at merge time, modvalidate's validateFragment enforces
// the same rule at module-install time).
var BaseModel = mustLoadBaseModel()

func mustLoadBaseModel() Model {
	m, err := LoadModel(modelJSON)
	if err != nil {
		panic("engine: embedded model.json failed to load: " + err.Error())
	}
	return m
}

// IsBaseType reports whether typ is one of the platform base model's own object types — used by
// fragment.Load and modvalidate to refuse a module fragment that declares/redefines a base type,
// rather than silently letting the fragment's definition shadow (or be shadowed by) the base
// model's.
func IsBaseType(typ string) bool {
	_, ok := BaseModel[typ]
	return ok
}
