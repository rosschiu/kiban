// SPDX-License-Identifier: Apache-2.0

package fragment

import (
	"context"
	"strings"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

const moduleAFragment = `{
  "a_widget": {
    "company_module": { "this": true },
    "viewer": { "this": true }
  }
}`

const moduleBFragment = `{
  "b_widget": {
    "company_module": { "this": true },
    "viewer": { "this": true }
  }
}`

// TestDisabledModuleInert proves: a module unknown to (or disabled per) the registry
// contributes nothing to the effective model, and a tuple granted under its object type
// answers false on Check — never an error, never an allow. Module A stays known+enabled
// throughout (control case: its tuples keep answering their real value).
func TestDisabledModuleInert(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)
	en := &engine.Engine{Pool: pool}

	// Seed both modules' fragments — B starts active, then gets disabled mid-test.
	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key IN ('mod-a','mod-b')`)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('mod-a', $1::jsonb, true)`, moduleAFragment)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('mod-b', $1::jsonb, true)`, moduleBFragment)

	// Seed tuples for both — a real grant on each.
	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ('inert-a1','inert-b1')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('a_widget','inert-a1','viewer','user','inert-user')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('b_widget','inert-b1','viewer','user','inert-user')`)

	knownEnabled := map[string]bool{"mod-a": true, "mod-b": true}

	loaded, err := Load(ctx, pool, knownEnabled)
	if err != nil {
		t.Fatalf("Load (both enabled): %v", err)
	}
	allowedA, err := Check(ctx, en, loaded, "a_widget", "inert-a1", "viewer", "user", "inert-user")
	if err != nil || !allowedA {
		t.Fatalf("mod-a (enabled) check: allowed=%v err=%v, want true/nil", allowedA, err)
	}
	allowedB, err := Check(ctx, en, loaded, "b_widget", "inert-b1", "viewer", "user", "inert-user")
	if err != nil || !allowedB {
		t.Fatalf("mod-b (enabled) check: allowed=%v err=%v, want true/nil", allowedB, err)
	}

	// Now disable mod-b (module-registry perspective: it's known but disabled).
	knownEnabled = map[string]bool{"mod-a": true, "mod-b": false}
	loadedDisabled, err := Load(ctx, pool, knownEnabled)
	if err != nil {
		t.Fatalf("Load (mod-b disabled): %v", err)
	}
	// Control: mod-a is unaffected.
	allowedA2, err := Check(ctx, en, loadedDisabled, "a_widget", "inert-a1", "viewer", "user", "inert-user")
	if err != nil || !allowedA2 {
		t.Fatalf("mod-a after mod-b disabled: allowed=%v err=%v, want true/nil", allowedA2, err)
	}
	// The disabled-module case: mod-b's tuple (still present in authz.tuple) answers false, no error.
	allowedB2, err := Check(ctx, en, loadedDisabled, "b_widget", "inert-b1", "viewer", "user", "inert-user")
	if err != nil {
		t.Fatalf("mod-b (disabled) check returned an ERROR, want false/nil: %v", err)
	}
	if allowedB2 {
		t.Fatalf("mod-b (disabled) check returned allowed=true, want false (disabled-module inertness)")
	}

	// Unknown-to-the-registry module (never in knownEnabled at all) behaves the same as disabled.
	knownEnabled = map[string]bool{"mod-a": true} // mod-b absent entirely
	loadedUnknown, err := Load(ctx, pool, knownEnabled)
	if err != nil {
		t.Fatalf("Load (mod-b unknown): %v", err)
	}
	allowedB3, err := Check(ctx, en, loadedUnknown, "b_widget", "inert-b1", "viewer", "user", "inert-user")
	if err != nil {
		t.Fatalf("mod-b (unknown module) check returned an ERROR, want false/nil: %v", err)
	}
	if allowedB3 {
		t.Fatalf("mod-b (unknown module) check returned allowed=true, want false (disabled-module inertness)")
	}

	// A truly unknown type (declared by NO fragment at all) still fails closed with an error.
	_, err = Check(ctx, en, loadedUnknown, "nonexistent_type", "x", "viewer", "user", "inert-user")
	if err == nil {
		t.Fatalf("check against a type no fragment ever declared: want an UNKNOWN_TYPE error, got nil")
	}
}

// notifLikeFragment mirrors modules/notification/authz.fragment.json's "relations" shape
// closely enough to prove a base+fragment compose. It never exercises the company_module#member
// branch (the base model has no such relation); the shipped notification_channel#viewer union
// only reaches that branch when a company_module tupleset row exists, which this test never grants.
const notifLikeFragment = `{
  "frag_channel": {
    "company_module": { "this": true },
    "owner": { "this": true },
    "editor": { "union": [{ "this": true }, { "computedUserset": "owner" }] }
  }
}`

// TestBaseModelAlwaysLoaded proves the platform base model (internal/authz/engine.BaseModel) is
// part of the effective model UNCONDITIONALLY — resolvable with zero module fragments
// known/enabled at all, never inert.
func TestBaseModelAlwaysLoaded(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)
	en := &engine.Engine{Pool: pool}

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ('frag-sys1','frag-cm-zero')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('system','frag-sys1','superadmin','user','frag-superadmin')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('company_module','frag-cm-zero','system','system','frag-sys1')`)

	loaded, err := Load(ctx, pool, map[string]bool{}) // zero modules known+enabled
	if err != nil {
		t.Fatalf("Load with zero fragments: %v", err)
	}
	for _, base := range []string{"user", "system", "module", "company", "company_module"} {
		if _, ok := loaded.Model[base]; !ok {
			t.Errorf("Load with zero fragments: base type %q missing from effective model", base)
		}
		if !loaded.AllowedTypes[base] {
			t.Errorf("Load with zero fragments: base type %q missing from AllowedTypes", base)
		}
	}

	// The base model's own system#superadmin -> company_module#admin tupleToUserset chain
	// resolves with zero fragments installed — proves the base model is genuinely EFFECTIVE, not
	// just present as an empty map.
	allowed, err := Check(ctx, en, loaded, "company_module", "frag-cm-zero", "admin", "user", "frag-superadmin")
	if err != nil {
		t.Fatalf("company_module#admin via system#superadmin, zero fragments: %v", err)
	}
	if !allowed {
		t.Fatalf("company_module#admin via system#superadmin, zero fragments: got false, want true")
	}
}

// TestBaseAndModuleFragmentCompose proves base + an active module fragment resolve together:
// the base model's company_module#admin AND the fragment's own frag_channel#owner/editor both
// answer correctly from the SAME Loaded model.
func TestBaseAndModuleFragmentCompose(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)
	en := &engine.Engine{Pool: pool}

	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = 'frag-notif-like'`)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('frag-notif-like', $1::jsonb, true)`, notifLikeFragment)

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ('frag-cm-compose','frag-chan-1')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('company_module','frag-cm-compose','admin','user','frag-cm-admin')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('frag_channel','frag-chan-1','owner','user','frag-chan-owner')`)

	loaded, err := Load(ctx, pool, map[string]bool{"frag-notif-like": true})
	if err != nil {
		t.Fatalf("Load (base + module fragment): %v", err)
	}
	if _, ok := loaded.Model["company_module"]; !ok {
		t.Fatalf("base type company_module missing from a compose Load")
	}
	if _, ok := loaded.Model["frag_channel"]; !ok {
		t.Fatalf("fragment type frag_channel missing from a compose Load")
	}

	baseOK, err := Check(ctx, en, loaded, "company_module", "frag-cm-compose", "admin", "user", "frag-cm-admin")
	if err != nil || !baseOK {
		t.Fatalf("base company_module#admin in compose: allowed=%v err=%v, want true/nil", baseOK, err)
	}
	fragOwnerOK, err := Check(ctx, en, loaded, "frag_channel", "frag-chan-1", "owner", "user", "frag-chan-owner")
	if err != nil || !fragOwnerOK {
		t.Fatalf("fragment frag_channel#owner in compose: allowed=%v err=%v, want true/nil", fragOwnerOK, err)
	}
	fragEditorViaOwnerOK, err := Check(ctx, en, loaded, "frag_channel", "frag-chan-1", "editor", "user", "frag-chan-owner")
	if err != nil || !fragEditorViaOwnerOK {
		t.Fatalf("fragment frag_channel#editor (via owner) in compose: allowed=%v err=%v, want true/nil", fragEditorViaOwnerOK, err)
	}
}

// TestFragmentRedeclaringBaseTypeRefused proves the merge-time half of the subset-wall
// assertion: an ACTIVE, known-enabled fragment that declares a base type (company_module) as one
// of its own top-level relations is refused (Load returns an error), never silently merged over
// (or under) the base model's own definition.
func TestFragmentRedeclaringBaseTypeRefused(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)

	const badFragment = `{
  "company_module": {
    "bogus": { "this": true }
  }
}`
	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = 'frag-bad-redeclare'`)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('frag-bad-redeclare', $1::jsonb, true)`, badFragment)

	_, err := Load(ctx, pool, map[string]bool{"frag-bad-redeclare": true})
	if err == nil {
		t.Fatalf("Load with a fragment redeclaring base type company_module: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "company_module") || !strings.Contains(err.Error(), "base type") {
		t.Fatalf("Load error %q does not name the offending base type / call it out as a base type", err.Error())
	}
}

// TestFragmentWithoutCompanyModuleAnchorRefused proves the merge-time half of the company-anchor contract
// rule: an active, known-enabled fragment whose object type does not define `company_module`
// as a direct relation is refused — such an object could never be bound to a company by the
// decision layer, so it must never enter the effective model.
func TestFragmentWithoutCompanyModuleAnchorRefused(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)

	const noAnchor = `{
  "frag_unanchored": {
    "viewer": { "this": true }
  }
}`
	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = 'frag-no-anchor'`)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('frag-no-anchor', $1::jsonb, true)`, noAnchor)
	t.Cleanup(func() { mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = 'frag-no-anchor'`) })

	_, err := Load(ctx, pool, map[string]bool{"frag-no-anchor": true})
	if err == nil || !strings.Contains(err.Error(), "company_module") {
		t.Fatalf("Load with an unanchored object type: want an error naming company_module, got %v", err)
	}
}

// TestInertHoldsWithBaseModelPresent re-proves disable/re-enable inertness now that Load always
// starts from the base model: a disabled module fragment's own type stays inert exactly as
// before, and the base model's own types are never affected by any module's enabled state.
func TestInertHoldsWithBaseModelPresent(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)
	en := &engine.Engine{Pool: pool}

	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = 'inert-mod'`)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('inert-mod', $1::jsonb, true)`, notifLikeFragment)

	mustExec(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ('inert-cm','inert-chan')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('company_module','inert-cm','admin','user','inert-admin')`)
	mustExec(t, pool, `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id) VALUES ('frag_channel','inert-chan','owner','user','inert-owner')`)

	// Enabled: both base and fragment types resolve.
	loadedEnabled, err := Load(ctx, pool, map[string]bool{"inert-mod": true})
	if err != nil {
		t.Fatalf("Load (enabled): %v", err)
	}
	if ok, err := Check(ctx, en, loadedEnabled, "company_module", "inert-cm", "admin", "user", "inert-admin"); err != nil || !ok {
		t.Fatalf("base company_module#admin (module enabled): allowed=%v err=%v, want true/nil", ok, err)
	}
	if ok, err := Check(ctx, en, loadedEnabled, "frag_channel", "inert-chan", "owner", "user", "inert-owner"); err != nil || !ok {
		t.Fatalf("fragment frag_channel#owner (module enabled): allowed=%v err=%v, want true/nil", ok, err)
	}

	// Disabled: fragment type goes inert (false, no error); base model UNAFFECTED.
	loadedDisabled, err := Load(ctx, pool, map[string]bool{"inert-mod": false})
	if err != nil {
		t.Fatalf("Load (disabled): %v", err)
	}
	if ok, err := Check(ctx, en, loadedDisabled, "company_module", "inert-cm", "admin", "user", "inert-admin"); err != nil || !ok {
		t.Fatalf("base company_module#admin (module disabled): allowed=%v err=%v, want true/nil (base model unaffected by module state)", ok, err)
	}
	ok, err := Check(ctx, en, loadedDisabled, "frag_channel", "inert-chan", "owner", "user", "inert-owner")
	if err != nil {
		t.Fatalf("fragment frag_channel#owner (module disabled) returned an ERROR, want false/nil: %v", err)
	}
	if ok {
		t.Fatalf("fragment frag_channel#owner (module disabled) returned allowed=true, want false (disabled-module inertness)")
	}
}

// TestFragmentDeclaredByTwoModulesRefused proves the merge-time half of "one module owns an
// object type": two active, known-enabled fragments declaring the same
// type make Load fail, naming both modules — never a silent last-wins by row order.
func TestFragmentDeclaredByTwoModulesRefused(t *testing.T) {
	ctx := context.Background()
	pool := authzPool(t)

	const shared = `{"dup_shared": {"company_module": {"this": true}, "owner": {"this": true}}}`
	mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key IN ('dup-first', 'dup-second')`)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM authz.model_fragment WHERE module_key IN ('dup-first', 'dup-second')`)
	})
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('dup-first', $1::jsonb, true)`, shared)
	mustExec(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ('dup-second', $1::jsonb, true)`, shared)

	_, err := Load(ctx, pool, map[string]bool{"dup-first": true, "dup-second": true})
	if err == nil {
		t.Fatal("Load with two modules declaring dup_shared: want an error, got nil")
	}
	for _, want := range []string{"dup_shared", "dup-first", "dup-second"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Load error %q does not name %q", err.Error(), want)
		}
	}

	// With only one of them enabled the type has one owner and the model loads.
	if _, err := Load(ctx, pool, map[string]bool{"dup-first": true}); err != nil {
		t.Fatalf("Load with a single owner: %v", err)
	}
}
