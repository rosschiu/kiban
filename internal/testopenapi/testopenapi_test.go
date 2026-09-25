// SPDX-License-Identifier: Apache-2.0

package testopenapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadModule_AllFourModules(t *testing.T) {
	for _, m := range []string{"docs", "helpdesk", "notification", "timesheet"} {
		if _, err := LoadModule(m); err != nil {
			t.Errorf("LoadModule(%q): %v", m, err)
		}
	}
}

func TestValidateResponse_HealthEndpoint_Passes(t *testing.T) {
	spec, err := LoadModule("docs")
	if err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/docs/health", nil)
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	spec.ValidateResponse(t, req, rec)
}

// fakeTB records the Fatalf call instead of actually failing the enclosing test — this file's
// own proof that ValidateResponse DETECTS a schema violation, not just that it passes the happy
// path (a check that never fails on bad input is unproven).
type fakeTB struct {
	failed  bool
	message string
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.message = format
}

func TestValidateResponse_WrongStatusCode_Fails(t *testing.T) {
	spec, err := LoadModule("docs")
	if err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/docs/health", nil)
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusTeapot) // 418 is not declared for GET /health
	ft := &fakeTB{}
	spec.ValidateResponse(ft, req, rec)
	if !ft.failed {
		t.Fatal("expected ValidateResponse to fail for an undeclared status code")
	}
}

func TestValidateResponse_BodyWrongFieldType_Fails(t *testing.T) {
	spec, err := LoadModule("docs")
	if err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/docs/v1/companies/11111111-1111-1111-1111-111111111111/documents/22222222-2222-2222-2222-222222222222", nil)
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusOK)
	rec.Body.WriteString(`{"data":{"id":12345}}`) // Document.id is declared string/uuid, not a number.
	ft := &fakeTB{}
	spec.ValidateResponse(ft, req, rec)
	if !ft.failed {
		t.Fatal("expected ValidateResponse to fail for a field of the wrong type")
	}
}

func TestValidateResponse_NoMatchingRoute_Fails(t *testing.T) {
	spec, err := LoadModule("docs")
	if err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/docs/v1/not-a-real-path", nil)
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	ft := &fakeTB{}
	spec.ValidateResponse(ft, req, rec)
	if !ft.failed || !strings.Contains(ft.message, "no documented operation") {
		t.Fatalf("expected a 'no documented operation' failure, got failed=%v message=%q", ft.failed, ft.message)
	}
}
