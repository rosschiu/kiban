// SPDX-License-Identifier: Apache-2.0

package ratchetguard

import "testing"

// TestCompare_CatchesDeliberateLowering proves that a deliberate min-lowering (simulated here as
// two in-memory ratchet documents — no git plumbing needed to prove the comparison logic itself
// is correct; cmd/ratchetguard's main_test.go covers the end-to-end git behavior) is reported as
// a violation.
func TestCompare_CatchesDeliberateLowering(t *testing.T) {
	oldRatchet := map[string]Entry{
		"internal/authz/engine": {Min: 95.0, Floor: 95},
		"modules/docs/service":  {Min: 80.0, Floor: 80},
	}
	lowered := map[string]Entry{
		"internal/authz/engine": {Min: 95.0, Floor: 95},
		"modules/docs/service":  {Min: 70.0, Floor: 80}, // deliberately lowered
	}

	violations := Compare(oldRatchet, lowered)
	if len(violations) != 1 {
		t.Fatalf("Compare(old, lowered) = %v, want exactly 1 violation", violations)
	}
	want := `scope "modules/docs/service" min DECREASED: 80.0000 -> 70.0000 — coverage/ratchet.json minimums may only ever increase`
	if violations[0] != want {
		t.Fatalf("violation message = %q, want %q", violations[0], want)
	}
}

// TestCompare_CatchesRemovedScope proves removing a scope entirely (which would silently
// un-gate it, the same regression a min-decrease produces) is also caught.
func TestCompare_CatchesRemovedScope(t *testing.T) {
	oldRatchet := map[string]Entry{
		"internal/livestack": {Min: 95.0, Floor: 95},
	}
	newRatchet := map[string]Entry{}

	violations := Compare(oldRatchet, newRatchet)
	if len(violations) != 1 {
		t.Fatalf("Compare(old, new) = %v, want exactly 1 violation", violations)
	}
	want := `scope "internal/livestack" was REMOVED from coverage/ratchet.json (had min=95.0) — removing a scope's gate is a min-decrease in disguise`
	if violations[0] != want {
		t.Fatalf("violation message = %q, want %q", violations[0], want)
	}
}

// TestCompare_AllowsIncreaseAndNewScopes proves the non-violating shapes stay silent: a raised
// min (backfill progress) and a brand-new scope (a package just added to the ratchet) are not
// flagged.
func TestCompare_AllowsIncreaseAndNewScopes(t *testing.T) {
	oldRatchet := map[string]Entry{
		"modules/docs/service": {Min: 80.0, Floor: 80},
	}
	newRatchet := map[string]Entry{
		"modules/docs/service":   {Min: 82.0, Floor: 80}, // raised — fine
		"modules/newmod/service": {Min: 0.0, Floor: 80},  // brand new scope — fine
	}

	violations := Compare(oldRatchet, newRatchet)
	if len(violations) != 0 {
		t.Fatalf("Compare(old, new) = %v, want no violations", violations)
	}
}

func TestParse_SkipsCommentKeys(t *testing.T) {
	doc := []byte(`{
		"_comment": "not a scope",
		"internal/authz/engine": {"min": 95.0, "floor": 95}
	}`)
	got, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Parse returned %d scopes, want 1 (the _comment key must be skipped): %v", len(got), got)
	}
	if got["internal/authz/engine"].Min != 95.0 {
		t.Fatalf("Parse: got %+v", got["internal/authz/engine"])
	}
}

func TestParse_RejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("Parse accepted malformed JSON")
	}
}
