// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_PlainEnv(t *testing.T) {
	t.Setenv("FOO", "bar")
	got, err := Load(Spec{{Name: "FOO", Required: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["FOO"] != "bar" {
		t.Errorf("FOO = %q, want %q", got["FOO"], "bar")
	}
}

func TestLoad_Default(t *testing.T) {
	got, err := Load(Spec{{Name: "UNSET_FIELD", Default: "fallback"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["UNSET_FIELD"] != "fallback" {
		t.Errorf("UNSET_FIELD = %q, want %q", got["UNSET_FIELD"], "fallback")
	}
}

func TestLoad_FileVariantWinsOverPlainEnv(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECRET", "from-env")
	t.Setenv("SECRET_FILE", secretPath)

	got, err := Load(Spec{{Name: "SECRET", Required: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["SECRET"] != "from-file" {
		t.Errorf("SECRET = %q, want %q", got["SECRET"], "from-file")
	}
}

func TestLoad_FileVariantAlone(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("only-file-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECRET2_FILE", secretPath)

	got, err := Load(Spec{{Name: "SECRET2", Required: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["SECRET2"] != "only-file-value" {
		t.Errorf("SECRET2 = %q, want %q", got["SECRET2"], "only-file-value")
	}
}

func TestLoad_MissingRequiredAllNamesNotJustFirst(t *testing.T) {
	t.Setenv("PRESENT_D", "value")
	_, err := Load(Spec{
		{Name: "MISSING_X", Required: true},
		{Name: "MISSING_Y", Required: true},
		{Name: "PRESENT_D", Required: true},
	})

	var missingErr *MissingError
	if !errors.As(err, &missingErr) {
		t.Fatalf("expected *MissingError, got %v (%T)", err, err)
	}
	if len(missingErr.Names) != 2 {
		t.Fatalf("expected exactly 2 missing names, got %v", missingErr.Names)
	}
	want := map[string]bool{"MISSING_X": true, "MISSING_Y": true}
	for _, n := range missingErr.Names {
		if !want[n] {
			t.Errorf("unexpected missing name %q", n)
		}
	}
}

func TestLoad_OptionalMissingNoError(t *testing.T) {
	got, err := Load(Spec{{Name: "OPTIONAL_UNSET", Required: false}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["OPTIONAL_UNSET"]; ok {
		t.Errorf("expected OPTIONAL_UNSET absent, got %q", got["OPTIONAL_UNSET"])
	}
}

// TestLoad_UnreadableFileIsAnErrorForOptionalAndRequired proves a SET but unreadable
// <NAME>_FILE never degrades silently: an optional field does not fall back to "" (or its env
// value/default) and a required one is not misreported as merely "missing" — both fail with an
// error naming the _FILE variable.
func TestLoad_UnreadableFileIsAnErrorForOptionalAndRequired(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "does-not-exist")
	for _, required := range []bool{false, true} {
		t.Setenv("UNREADABLE", "from-env")
		t.Setenv("UNREADABLE_FILE", missingPath)
		_, err := Load(Spec{{Name: "UNREADABLE", Required: required, Default: "dflt"}})
		if err == nil {
			t.Fatalf("required=%v: want an error for an unreadable _FILE, got nil", required)
		}
		var missing *MissingError
		if errors.As(err, &missing) {
			t.Fatalf("required=%v: got MissingError %v, want a distinct unreadable-file error", required, err)
		}
		if !strings.Contains(err.Error(), "UNREADABLE_FILE") {
			t.Fatalf("required=%v: error %q does not name UNREADABLE_FILE", required, err)
		}
	}
}

// TestLoad_RequiredEmptyEnvIsMissing: NAME= (set, empty) on a required field is reported as
// missing together with the unset ones — Compose passes an unset host variable through as an
// empty one, and that must stop the service at start-up.
func TestLoad_RequiredEmptyEnvIsMissing(t *testing.T) {
	t.Setenv("EMPTY_REQ", "")
	t.Setenv("PRESENT_REQ", "value")
	_, err := Load(Spec{
		{Name: "EMPTY_REQ", Required: true},
		{Name: "UNSET_REQ", Required: true},
		{Name: "PRESENT_REQ", Required: true},
	})

	var missingErr *MissingError
	if !errors.As(err, &missingErr) {
		t.Fatalf("expected *MissingError, got %v (%T)", err, err)
	}
	if got := strings.Join(missingErr.Names, ","); got != "EMPTY_REQ,UNSET_REQ" {
		t.Errorf("missing names = %q, want %q", got, "EMPTY_REQ,UNSET_REQ")
	}
}

// TestLoad_RequiredEmptyFileIsMissing: a required field whose <NAME>_FILE holds only
// whitespace resolves to "" and is missing, not a start with an empty secret.
func TestLoad_RequiredEmptyFileIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-secret")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("EMPTY_FILE_REQ_FILE", path)

	_, err := Load(Spec{{Name: "EMPTY_FILE_REQ", Required: true}})

	var missingErr *MissingError
	if !errors.As(err, &missingErr) {
		t.Fatalf("expected *MissingError, got %v (%T)", err, err)
	}
	if len(missingErr.Names) != 1 || missingErr.Names[0] != "EMPTY_FILE_REQ" {
		t.Errorf("missing names = %v, want [EMPTY_FILE_REQ]", missingErr.Names)
	}
}

// TestLoad_OptionalEmptyCountsAsSet: an optional field keeps "empty counts as set" — NAME=
// yields "" and skips the default, and an empty file does the same.
func TestLoad_OptionalEmptyCountsAsSet(t *testing.T) {
	t.Setenv("EMPTY_OPT", "")
	path := filepath.Join(t.TempDir(), "empty-optional")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv("EMPTY_FILE_OPT_FILE", path)

	got, err := Load(Spec{
		{Name: "EMPTY_OPT", Default: "fallback"},
		{Name: "EMPTY_FILE_OPT", Default: "fallback"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"EMPTY_OPT", "EMPTY_FILE_OPT"} {
		if v, ok := got[name]; !ok || v != "" {
			t.Errorf("%s = %q (present=%v), want present and empty", name, v, ok)
		}
	}
}

// TestLoad_EmptyFileVariableIsIgnored: NAME_FILE= (set, empty) is not a file to read; the plain
// variable is used as before.
func TestLoad_EmptyFileVariableIsIgnored(t *testing.T) {
	t.Setenv("PLAIN_REQ_FILE", "")
	t.Setenv("PLAIN_REQ", "plain-value")

	got, err := Load(Spec{{Name: "PLAIN_REQ", Required: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["PLAIN_REQ"] != "plain-value" {
		t.Errorf("PLAIN_REQ = %q, want %q", got["PLAIN_REQ"], "plain-value")
	}
}
