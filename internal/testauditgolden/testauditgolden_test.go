// SPDX-License-Identifier: Apache-2.0

package testauditgolden

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShape_KeysAndTypesOnly(t *testing.T) {
	got, err := Shape([]byte(`{"companyId":"11111111-1111-1111-1111-111111111111","recipients":3,"delivered":true,"tags":["a","b"],"meta":{"x":1},"note":null}`))
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	want := "companyId:string\ndelivered:bool\nmeta:object\nnote:null\nrecipients:number\ntags:array\n"
	if got != want {
		t.Fatalf("Shape() = %q, want %q", got, want)
	}
}

func TestShape_ValuesDoNotAffectOutput(t *testing.T) {
	a, err := Shape([]byte(`{"memberId":"aaaa","title":"Alpha"}`))
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	b, err := Shape([]byte(`{"memberId":"zzzz-different","title":"A wildly different title entirely"}`))
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	if a != b {
		t.Fatalf("shape should be value-independent: %q != %q", a, b)
	}
}

func TestShape_InvalidJSON(t *testing.T) {
	if _, err := Shape([]byte(`not json`)); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestAssertGolden_MatchesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "golden.txt")
	if err := os.WriteFile(path, []byte("a:string\n"), 0o644); err != nil {
		t.Fatalf("seed golden: %v", err)
	}
	AssertGolden(t, path, "a:string\n")
}

func TestAssertGolden_UpdateWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "golden.txt")
	t.Setenv("UPDATE_AUDIT_GOLDENS", "1")
	AssertGolden(t, path, "b:number\n")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "b:number\n" {
		t.Fatalf("golden = %q, want %q", string(got), "b:number\n")
	}
}

func TestMatches_DetectsMismatch(t *testing.T) {
	if Matches("a:string\n", "a:number\n") {
		t.Fatal("expected Matches to report a mismatch")
	}
	if !Matches("a:string\n", "a:string\n") {
		t.Fatal("expected Matches to report equal strings as matching")
	}
}
