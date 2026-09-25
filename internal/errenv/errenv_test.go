// SPDX-License-Identifier: Apache-2.0

package errenv

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestErrorCodesExactStrings(t *testing.T) {
	cases := map[string]string{
		CodeBadRequest:               "BAD_REQUEST",
		CodeAuthTokenMissing:         "AUTH_TOKEN_MISSING",
		CodeAuthTokenInvalid:         "AUTH_TOKEN_INVALID",
		CodeForbidden:                "FORBIDDEN",
		CodeAuthorizationDenied:      "AUTHORIZATION_DENIED",
		CodeModuleNotInstalled:       "MODULE_NOT_INSTALLED",
		CodeModuleDisabled:           "MODULE_DISABLED",
		CodeModuleDependencyMissing:  "MODULE_DEPENDENCY_MISSING",
		CodeNotFound:                 "NOT_FOUND",
		CodeConflict:                 "CONFLICT",
		CodeValidationError:          "VALIDATION_ERROR",
		CodeInternalError:            "INTERNAL_ERROR",
		CodeAuthorizationUnavailable: "AUTHORIZATION_UNAVAILABLE",
		CodeModuleUnavailable:        "MODULE_UNAVAILABLE",
		CodePayloadTooLarge:          "PAYLOAD_TOO_LARGE",
		CodeValidationFailed:         "VALIDATION_FAILED",
		CodeIdempotencyConflict:      "IDEMPOTENCY_CONFLICT",
		CodeGroupExternallyManaged:   "GROUP_EXTERNALLY_MANAGED",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("code constant = %q, want %q", got, want)
		}
	}
	if len(cases) != 18 {
		t.Fatalf("expected 18 codes covered, got %d", len(cases))
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		apiErr     APIError
		wantBody   string
		wantStatus int
	}{
		{
			name:       "without details",
			status:     404,
			apiErr:     APIError{Code: CodeNotFound, Message: "not found"},
			wantBody:   `{"error":{"code":"NOT_FOUND","message":"not found"}}` + "\n",
			wantStatus: 404,
		},
		{
			name:       "with details",
			status:     422,
			apiErr:     APIError{Code: CodeValidationError, Message: "invalid", Details: map[string]string{"field": "name"}},
			wantBody:   `{"error":{"code":"VALIDATION_ERROR","message":"invalid","details":{"field":"name"}}}` + "\n",
			wantStatus: 422,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteError(rec, tc.status, tc.apiErr)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if got := rec.Body.String(); got != tc.wantBody {
				t.Errorf("body = %q, want %q", got, tc.wantBody)
			}
		})
	}
}

func TestWriteData(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteData(rec, 200, map[string]int{"count": 3})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	want := `{"data":{"count":3}}` + "\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestPageJSONShape(t *testing.T) {
	p := Page[string]{Items: []string{"a", "b"}, Total: 2, Page: 1, PageSize: 25, TotalPages: 1}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"items":["a","b"],"total":2,"page":1,"pageSize":25,"totalPages":1}`
	if string(b) != want {
		t.Errorf("Page JSON = %s, want %s", b, want)
	}
}
