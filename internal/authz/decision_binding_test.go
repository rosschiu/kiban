// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/decision"
)

// --- Company binding: step 7 binds the checked object to the request's
// company before the relation check. Every branch of the binding rule is proven here against a
// recording fake engine; the batch path goes through the same rule per item. ---

// recordingEngine answers each (objType, objID, relation, subjType, subjID) from a table and
// records the calls, so a test can prove the anchor check ran (or did not) and in which order.
type recordingEngine struct {
	answers map[string]bool
	errOn   string
	calls   []string
}

func engineKey(objType, objID, relation, subjType, subjID string) string {
	return objType + ":" + objID + "#" + relation + "@" + subjType + ":" + subjID
}

func (e *recordingEngine) Check(ctx context.Context, objType, objID, relation, subjType, subjID string) (bool, error) {
	k := engineKey(objType, objID, relation, subjType, subjID)
	e.calls = append(e.calls, k)
	if k == e.errOn {
		return false, errors.New("engine boom")
	}
	return e.answers[k], nil
}

// fakeModel is a decision.RelationDefiner over a "type#relation" set — the effective model the
// binding rule consults to pick the anchor relation for a type.
type fakeModel map[string]bool

func (m fakeModel) Defines(objType, relation string) bool { return m[objType+"#"+relation] }

// bindingModel: "doc" is a module object (company_module anchor), "position" a base org object
// (company anchor), "orphan" defines neither.
var bindingModel = fakeModel{"doc#company_module": true, "doc#viewer": true, "position#company": true, "position#holder": true, "orphan#viewer": true}

func evidenceValue(ev []decision.Evidence, key string) (string, bool) {
	for _, e := range ev {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

func bindingRequest(objType, objID string) decision.Request {
	req := companyRequest()
	req.RequiresEligibility = false
	req.Object = decision.ObjectRef{Type: objType, ID: objID}
	return req
}

func TestDecisionBinding_CompanyObject(t *testing.T) {
	deps := happyDeps()
	d := decision.NewDecider(deps)

	if dec := d.Evaluate(context.Background(), bindingRequest("company", "company-1")); !dec.Allowed {
		t.Fatalf("own company: %+v, want allowed", dec)
	} else if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "true" {
		t.Fatalf("own company: objectCompany evidence = %q, want true", v)
	}

	dec := d.Evaluate(context.Background(), bindingRequest("company", "company-2"))
	if dec.Allowed || dec.Reason != decision.ReasonEngineDenied {
		t.Fatalf("foreign company: %+v, want ENGINE_DENIED", dec)
	}
	if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "false" {
		t.Fatalf("foreign company: objectCompany evidence = %q, want false", v)
	}
	if v, _ := evidenceValue(dec.Evidence, "object"); v != "company:company-2" {
		t.Fatalf("foreign company: object evidence = %q", v)
	}
	if _, ok := evidenceValue(dec.Evidence, "relation"); ok {
		t.Fatalf("foreign company: relation must not be evaluated after a failed binding: %+v", dec.Evidence)
	}
}

func TestDecisionBinding_CompanyModuleObject(t *testing.T) {
	d := decision.NewDecider(happyDeps())
	if dec := d.Evaluate(context.Background(), bindingRequest("company_module", "company-1/test-module")); !dec.Allowed {
		t.Fatalf("own module: %+v, want allowed", dec)
	}
	for _, id := range []string{"company-2/test-module", "company-1/other-module"} {
		dec := d.Evaluate(context.Background(), bindingRequest("company_module", id))
		if dec.Allowed || dec.Reason != decision.ReasonEngineDenied {
			t.Fatalf("%s: %+v, want ENGINE_DENIED", id, dec)
		}
		if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "false" {
			t.Fatalf("%s: objectCompany evidence = %q, want false", id, v)
		}
	}
}

func TestDecisionBinding_ModuleObjectAnchor(t *testing.T) {
	const (
		anchorKey   = "doc:d1#company_module@company_module:company-1/test-module"
		relationKey = "doc:d1#viewer@user:user-1"
	)

	t.Run("anchored object: anchor check runs before the relation check", func(t *testing.T) {
		eng := &recordingEngine{answers: map[string]bool{anchorKey: true, relationKey: true}}
		deps := happyDeps()
		deps.Engine = eng
		deps.Model = bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), bindingRequest("doc", "d1"))
		if !dec.Allowed {
			t.Fatalf("%+v, want allowed", dec)
		}
		if len(eng.calls) != 2 || eng.calls[0] != anchorKey || eng.calls[1] != relationKey {
			t.Fatalf("engine calls = %v, want [anchor, relation]", eng.calls)
		}
		if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "true" {
			t.Fatalf("objectCompany evidence = %q, want true", v)
		}
	})

	t.Run("unanchored object: ENGINE_DENIED, relation never evaluated", func(t *testing.T) {
		eng := &recordingEngine{answers: map[string]bool{relationKey: true}} // owner tuple present, anchor absent
		deps := happyDeps()
		deps.Engine = eng
		deps.Model = bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), bindingRequest("doc", "d1"))
		if dec.Allowed || dec.Reason != decision.ReasonEngineDenied {
			t.Fatalf("%+v, want ENGINE_DENIED", dec)
		}
		if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "false" {
			t.Fatalf("objectCompany evidence = %q, want false", v)
		}
		if len(eng.calls) != 1 {
			t.Fatalf("engine calls = %v, want only the anchor check", eng.calls)
		}
	})

	t.Run("anchor check error: DEPENDENCY_UNAVAILABLE, never a guess", func(t *testing.T) {
		eng := &recordingEngine{errOn: anchorKey}
		deps := happyDeps()
		deps.Engine = eng
		deps.Model = bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), bindingRequest("doc", "d1"))
		if dec.Allowed || dec.Reason != decision.ReasonDependencyUnavailable || dec.Dependency != "engine" || dec.Step != "relation_check" {
			t.Fatalf("%+v, want DEPENDENCY_UNAVAILABLE engine/relation_check", dec)
		}
	})
}

// TestDecisionBinding_BaseOrgObjectViaCompany covers the model-driven branch for base org
// types (position/group): a type whose effective model defines `company` binds through
// `<type>:<id>#company @ company:<companyId>` — the helpdesk holder-check shape.
func TestDecisionBinding_BaseOrgObjectViaCompany(t *testing.T) {
	const (
		anchorKey   = "position:p1#company@company:company-1"
		relationKey = "position:p1#holder@user:user-1"
	)
	req := bindingRequest("position", "p1")
	req.Relation = "holder"

	t.Run("position in the request's company: allowed", func(t *testing.T) {
		eng := &recordingEngine{answers: map[string]bool{anchorKey: true, relationKey: true}}
		deps := happyDeps()
		deps.Engine, deps.Model = eng, bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), req)
		if !dec.Allowed {
			t.Fatalf("%+v, want allowed", dec)
		}
		if len(eng.calls) != 2 || eng.calls[0] != anchorKey || eng.calls[1] != relationKey {
			t.Fatalf("engine calls = %v, want [company anchor, relation]", eng.calls)
		}
	})

	t.Run("position of another company: ENGINE_DENIED objectCompany=false, holder never evaluated", func(t *testing.T) {
		eng := &recordingEngine{answers: map[string]bool{relationKey: true}} // holder yes, anchor points elsewhere
		deps := happyDeps()
		deps.Engine, deps.Model = eng, bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), req)
		if dec.Allowed || dec.Reason != decision.ReasonEngineDenied {
			t.Fatalf("%+v, want ENGINE_DENIED", dec)
		}
		if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "false" {
			t.Fatalf("objectCompany evidence = %q, want false", v)
		}
		if len(eng.calls) != 1 {
			t.Fatalf("engine calls = %v, want only the company anchor check", eng.calls)
		}
	})

	t.Run("company anchor check error: DEPENDENCY_UNAVAILABLE", func(t *testing.T) {
		eng := &recordingEngine{errOn: anchorKey}
		deps := happyDeps()
		deps.Engine, deps.Model = eng, bindingModel
		dec := decision.NewDecider(deps).Evaluate(context.Background(), req)
		if dec.Reason != decision.ReasonDependencyUnavailable || dec.Dependency != "engine" || dec.Step != "relation_check" {
			t.Fatalf("%+v, want DEPENDENCY_UNAVAILABLE engine/relation_check", dec)
		}
	})
}

// TestDecisionBinding_UnbindableType: a type defining neither `company` nor `company_module`
// (or no model at all) can never be bound — clean ENGINE_DENIED, no engine call.
func TestDecisionBinding_UnbindableType(t *testing.T) {
	for name, model := range map[string]decision.RelationDefiner{"type without anchor": bindingModel, "nil model": nil} {
		t.Run(name, func(t *testing.T) {
			eng := &recordingEngine{answers: map[string]bool{"orphan:o1#viewer@user:user-1": true}}
			deps := happyDeps()
			deps.Engine, deps.Model = eng, model
			dec := decision.NewDecider(deps).Evaluate(context.Background(), bindingRequest("orphan", "o1"))
			if dec.Allowed || dec.Reason != decision.ReasonEngineDenied {
				t.Fatalf("%+v, want ENGINE_DENIED", dec)
			}
			if v, _ := evidenceValue(dec.Evidence, "objectCompany"); v != "false" {
				t.Fatalf("objectCompany evidence = %q, want false", v)
			}
			if len(eng.calls) != 0 {
				t.Fatalf("engine calls = %v, want none (nothing to bind through)", eng.calls)
			}
		})
	}
}

func TestDecisionBinding_GlobalScopeUnchanged(t *testing.T) {
	eng := &recordingEngine{answers: map[string]bool{}}
	deps := happyDeps()
	deps.Engine = eng
	req := globalRequest()
	req.Object = decision.ObjectRef{Type: "doc", ID: "d1"}
	req.Relation = "viewer"
	dec := decision.NewDecider(deps).Evaluate(context.Background(), req)
	if !dec.Allowed || len(eng.calls) != 0 {
		t.Fatalf("global scope: %+v calls=%v — global has no object leg and must not bind", dec, eng.calls)
	}
}

func TestDecisionBinding_Batch(t *testing.T) {
	eng := &recordingEngine{answers: map[string]bool{
		"doc:anchored#company_module@company_module:company-1/test-module": true,
		"doc:anchored#viewer@user:user-1":                                  true,
		"doc:foreign#viewer@user:user-1":                                   true, // has the relation, lacks the anchor
		"company_module:company-1/test-module#viewer@user:user-1":          true,
	}}
	deps := happyDeps()
	deps.Engine = eng
	deps.Model = bindingModel
	base := companyRequest()
	base.RequiresEligibility = false
	items := []decision.BatchItem{
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-1/test-module"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "company_module", ID: "company-2/test-module"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "doc", ID: "anchored"}, Relation: "viewer"},
		{Object: decision.ObjectRef{Type: "doc", ID: "foreign"}, Relation: "viewer"},
	}
	results := decision.NewDecider(deps).EvaluateBatch(context.Background(), base, items)
	wantAllowed := []bool{true, false, true, false}
	for i, r := range results {
		if r.Decision.Allowed != wantAllowed[i] {
			t.Fatalf("item %d (%s:%s): allowed=%v, want %v (%+v)", i, r.Item.Object.Type, r.Item.Object.ID, r.Decision.Allowed, wantAllowed[i], r.Decision)
		}
		if !wantAllowed[i] {
			if r.Decision.Reason != decision.ReasonEngineDenied {
				t.Fatalf("item %d: reason=%s, want ENGINE_DENIED", i, r.Decision.Reason)
			}
			if v, _ := evidenceValue(r.Decision.Evidence, "objectCompany"); v != "false" {
				t.Fatalf("item %d: objectCompany evidence = %q, want false", i, v)
			}
		}
	}
}
