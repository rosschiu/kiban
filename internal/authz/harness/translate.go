// SPDX-License-Identifier: Apache-2.0

//go:build harness

// Package harness is the differential conformance harness: it starts a real
// `openfga/openfga` container, translates the engine's model into an OpenFGA authorization
// model, loads IDENTICAL tuples into both authz.tuple and the OpenFGA store, and replays (a)
// the engine's vectors.json correctness floor and (b) 5,000 seeded random checks over
// loadgen-shaped data — any single divergence fails the test.
package harness

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// directTypesByRel parses internal/authz/harness/model.fga's `define <rel>: [<types>] ...` bracket
// syntax to recover, per (objectType, relation), the set of directly-assignable subject shapes
// (plain types like "user"/"system"/"company", or userset types like "access_bundle" for a
// `[access_bundle]`-typed relation reference) — information engine.Model itself doesn't carry
// (its `this` branches are generic: "match any row", independent of subject type). This is a
// mechanical, line-based parse of a fixed, checked-in file — not a general FGA DSL parser.
var defineLineRe = regexp.MustCompile(`^\s*define\s+([a-z_]+):\s*(.*)$`)
var bracketRe = regexp.MustCompile(`\[([a-zA-Z0-9_,#\s]+)]`)

func parseDirectTypes(dslPath string) (map[string]map[string][]string, error) {
	f, err := os.Open(dslPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dslPath, err)
	}
	defer f.Close()

	out := map[string]map[string][]string{}
	var curType string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "type ") {
			curType = strings.TrimSpace(strings.TrimPrefix(trimmed, "type "))
			if out[curType] == nil {
				out[curType] = map[string][]string{}
			}
			continue
		}
		if m := defineLineRe.FindStringSubmatch(line); m != nil && curType != "" {
			rel := m[1]
			bm := bracketRe.FindStringSubmatch(m[2])
			if bm == nil {
				continue // no bracket => no `this` leg on this relation
			}
			var types []string
			for _, t := range strings.Split(bm[1], ",") {
				types = append(types, strings.TrimSpace(t))
			}
			out[curType][rel] = types
		}
	}
	return out, scanner.Err()
}

// --- OpenFGA JSON authorization model shapes (schema 1.1 REST API) ---

type fgaTypeDef struct {
	Type      string                `json:"type"`
	Relations map[string]fgaUserset `json:"relations,omitempty"`
	Metadata  *fgaMetadata          `json:"metadata,omitempty"`
}

type fgaMetadata struct {
	Relations map[string]fgaRelMetadata `json:"relations,omitempty"`
}

type fgaRelMetadata struct {
	DirectlyRelatedUserTypes []fgaRelRef `json:"directly_related_user_types,omitempty"`
}

type fgaRelRef struct {
	Type     string `json:"type"`
	Relation string `json:"relation,omitempty"`
}

type fgaUserset struct {
	This            *struct{}           `json:"this,omitempty"`
	ComputedUserset *fgaObjectRelation  `json:"computedUserset,omitempty"`
	TupleToUserset  *fgaTupleToUserset  `json:"tupleToUserset,omitempty"`
	Union           *fgaUsersetChildren `json:"union,omitempty"`
}

type fgaObjectRelation struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
}

type fgaTupleToUserset struct {
	Tupleset        fgaObjectRelation `json:"tupleset"`
	ComputedUserset fgaObjectRelation `json:"computedUserset"`
}

type fgaUsersetChildren struct {
	Child []fgaUserset `json:"child"`
}

type fgaModel struct {
	SchemaVersion   string       `json:"schema_version"`
	TypeDefinitions []fgaTypeDef `json:"type_definitions"`
}

// BuildOpenFGAModel translates engine.Model (this/computedUserset/tupleToUserset/union — the
// exact supported subset, already validated by engine.LoadModel) into an OpenFGA JSON
// authorization model, using dslPath (internal/authz/harness/model.fga) to recover each `this`
// leg's directly-assignable subject types. extraUsersetTypes lets a caller widen a relation's
// directly_related_user_types beyond the DSL — used ONLY for the two vectors.json cases the
// DSL's own bracket doesn't cover (see harness_test.go's excludedVectors: engine.Check has no
// per-relation type restriction at write/read time,
// OpenFGA enforces one — those two vectors are excluded from the differential replay, not
// force-fit into the model).
func BuildOpenFGAModel(m engine.Model, dslPath string) (fgaModel, error) {
	directTypes, err := parseDirectTypes(dslPath)
	if err != nil {
		return fgaModel{}, err
	}

	model := fgaModel{SchemaVersion: "1.1"}

	for _, typ := range sortedModelTypes(m) {
		rels := m[typ]
		td := fgaTypeDef{Type: typ, Relations: map[string]fgaUserset{}, Metadata: &fgaMetadata{Relations: map[string]fgaRelMetadata{}}}
		for rel, expr := range rels {
			td.Relations[rel] = translateExpr(expr)
			if types, ok := directTypes[typ][rel]; ok {
				var refs []fgaRelRef
				for _, t := range types {
					if strings.Contains(t, "#") {
						parts := strings.SplitN(t, "#", 2)
						refs = append(refs, fgaRelRef{Type: parts[0], Relation: parts[1]})
					} else {
						refs = append(refs, fgaRelRef{Type: t})
					}
				}
				td.Metadata.Relations[rel] = fgaRelMetadata{DirectlyRelatedUserTypes: refs}
			}
		}
		model.TypeDefinitions = append(model.TypeDefinitions, td)
	}
	return model, nil
}

func sortedModelTypes(m engine.Model) []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	// stable, deterministic order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func translateExpr(e engine.Expr) fgaUserset {
	switch {
	case e.IsThis():
		return fgaUserset{This: &struct{}{}}
	case e.ComputedUsersetRel() != "":
		return fgaUserset{ComputedUserset: &fgaObjectRelation{Object: "", Relation: e.ComputedUsersetRel()}}
	case e.TupleToUsersetExpr() != nil:
		ttu := e.TupleToUsersetExpr()
		return fgaUserset{TupleToUserset: &fgaTupleToUserset{
			Tupleset:        fgaObjectRelation{Object: "", Relation: ttu.Tupleset},
			ComputedUserset: fgaObjectRelation{Object: "", Relation: ttu.ComputedUserset},
		}}
	case e.UnionChildren() != nil:
		children := make([]fgaUserset, 0, len(e.UnionChildren()))
		for _, c := range e.UnionChildren() {
			children = append(children, translateExpr(c))
		}
		return fgaUserset{Union: &fgaUsersetChildren{Child: children}}
	default:
		return fgaUserset{This: &struct{}{}}
	}
}
