// SPDX-License-Identifier: Apache-2.0

// Package contracts holds cross-language drift pins: checked-in goldens both a Go test and a
// TypeScript (vitest) test compare against, so a change to the Go side alone (or the TS side
// alone) fails its OWN suite rather than silently drifting until a caller matches on a string
// that no longer means what the other language thinks it means.
//
// contracts/wire-enums.json is the golden for internal/errenv's canonical
// error codes and internal/authz/decision's Reason enum, mirrored on the TS side by
// web/sdk/src/types.ts's ApiErrorCode/EffectiveAccessReason (proven by
// web/sdk/test/wireEnums.test.ts against the SAME file). "Exact strings are contract" — see
// both source packages' own doc comments.
//
// Update procedure: change contracts/wire-enums.json deliberately (add/remove/rename an entry),
// then update internal/errenv (or internal/authz/decision) AND web/sdk/src/types.ts to match, in
// the same change set. Whichever side you forget, its own test fails.
package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/errenv"
)

type wireEnumsGolden struct {
	APIErrorCodes          map[string]string `json:"apiErrorCodes"`
	EffectiveAccessReasons map[string]string `json:"effectiveAccessReasons"`
}

// goldenPath resolves contracts/wire-enums.json relative to THIS source file (not the working
// directory `go test` happens to run from), so the test works the same via `go test ./...` from
// the repo root and via `go test .` from this package's own directory.
func goldenPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this file's own path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "contracts", "wire-enums.json")
}

func loadGolden(t *testing.T) wireEnumsGolden {
	t.Helper()
	raw, err := os.ReadFile(goldenPath(t))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g wireEnumsGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return g
}

// goErrorCodes mirrors web/sdk/src/types.ts's ApiErrorCode key-by-key: this map's keys are the
// same friendly names the TS object uses, so both sides can be compared against the identical
// golden. Any new internal/errenv code must be added HERE (as well as to the golden and to
// types.ts) or this test won't know to check it — TestAPIErrorCodes_EveryGoConstantIsGolden
// below guards against a code silently added to errenv.go without ever reaching this map.
func goErrorCodes() map[string]string {
	return map[string]string{
		"BadRequest":               errenv.CodeBadRequest,
		"AuthTokenMissing":         errenv.CodeAuthTokenMissing,
		"AuthTokenInvalid":         errenv.CodeAuthTokenInvalid,
		"Forbidden":                errenv.CodeForbidden,
		"AuthorizationDenied":      errenv.CodeAuthorizationDenied,
		"ModuleNotInstalled":       errenv.CodeModuleNotInstalled,
		"ModuleDisabled":           errenv.CodeModuleDisabled,
		"ModuleDependencyMissing":  errenv.CodeModuleDependencyMissing,
		"NotFound":                 errenv.CodeNotFound,
		"Conflict":                 errenv.CodeConflict,
		"ValidationError":          errenv.CodeValidationError,
		"InternalError":            errenv.CodeInternalError,
		"AuthorizationUnavailable": errenv.CodeAuthorizationUnavailable,
		"ModuleUnavailable":        errenv.CodeModuleUnavailable,
		"PayloadTooLarge":          errenv.CodePayloadTooLarge,
		"ValidationFailed":         errenv.CodeValidationFailed,
		"IdempotencyConflict":      errenv.CodeIdempotencyConflict,
		"GroupExternallyManaged":   errenv.CodeGroupExternallyManaged,
	}
}

func TestAPIErrorCodes_MatchGolden(t *testing.T) {
	golden := loadGolden(t).APIErrorCodes
	got := goErrorCodes()
	if len(got) != len(golden) {
		t.Errorf("code count = %d, golden has %d (added/removed a code without updating both)", len(got), len(golden))
	}
	for name, wantWire := range golden {
		gotWire, ok := got[name]
		if !ok {
			t.Errorf("golden has %q but internal/errenv (via this test's goErrorCodes map) does not", name)
			continue
		}
		if gotWire != wantWire {
			t.Errorf("errenv code %q = %q, golden wants %q", name, gotWire, wantWire)
		}
	}
	for name := range got {
		if _, ok := golden[name]; !ok {
			t.Errorf("internal/errenv has %q but golden does not — update contracts/wire-enums.json AND web/sdk/src/types.ts", name)
		}
	}
}

// TestAPIErrorCodes_EveryGoConstantIsGolden guards goErrorCodes() itself against silently
// missing a real errenv.Code* constant: mirrors errenv_test.go's own TestErrorCodesExactStrings
// count check so a NEW Code* constant added to errenv.go without being
// added to this file's goErrorCodes map fails loudly here rather than passing by omission.
func TestAPIErrorCodes_EveryGoConstantIsGolden(t *testing.T) {
	const wantCount = 18
	if got := len(goErrorCodes()); got != wantCount {
		t.Fatalf("goErrorCodes() has %d entries, want %d — a Code* constant was added to or "+
			"removed from internal/errenv without updating this file's goErrorCodes map "+
			"(and contracts/wire-enums.json, and web/sdk/src/types.ts)", got, wantCount)
	}
}

func TestEffectiveAccessReasons_MatchGolden(t *testing.T) {
	golden := loadGolden(t).EffectiveAccessReasons
	if len(decision.AllReasons) != len(golden) {
		t.Errorf("decision.AllReasons has %d entries, golden has %d", len(decision.AllReasons), len(golden))
	}
	// decision.Reason values ARE the wire strings already (Reason is a string type whose
	// constants are the exact wire values), so the golden's VALUES are what decision.AllReasons
	// must reproduce as a set — the golden's KEYS are only there for the TS side's named-export
	// shape (EffectiveAccessReason.Allowed etc.) and have no separate Go-side identifier to
	// check against (decision.go's own const names already ARE ReasonAllowed etc., asserted
	// directly, not via this golden).
	wantWire := make(map[string]bool, len(golden))
	for _, wire := range golden {
		wantWire[wire] = true
	}
	gotWire := make(map[string]bool, len(decision.AllReasons))
	for _, r := range decision.AllReasons {
		gotWire[string(r)] = true
	}
	for wire := range wantWire {
		if !gotWire[wire] {
			t.Errorf("golden reason %q not found in decision.AllReasons", wire)
		}
	}
	for wire := range gotWire {
		if !wantWire[wire] {
			t.Errorf("decision.AllReasons has %q but golden does not — update contracts/wire-enums.json AND web/sdk/src/types.ts", wire)
		}
	}
}
