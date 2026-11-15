// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func TestCorrelation_GeneratesWhenAbsent(t *testing.T) {
	var gotID string
	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	gotID = rec.Header().Get(correlationHeader)
	if gotID == "" {
		t.Fatal("expected a generated correlation id header")
	}
	if len(gotID) != 32 { // hex-16 bytes = 32 hex chars
		t.Errorf("generated id length = %d, want 32", len(gotID))
	}
}

func TestCorrelation_PropagatesValidIncoming(t *testing.T) {
	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(correlationHeader, "client-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(correlationHeader); got != "client-supplied-id" {
		t.Errorf("echoed id = %q, want %q", got, "client-supplied-id")
	}
}

func TestCorrelation_ReplacesOversizeHeader(t *testing.T) {
	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	oversized := strings.Repeat("a", 129)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(correlationHeader, oversized)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get(correlationHeader)
	if got == oversized {
		t.Error("expected oversize correlation id to be replaced")
	}
	if got == "" {
		t.Error("expected a replacement correlation id")
	}
}

func TestCorrelation_ExactlyMaxLenAccepted(t *testing.T) {
	handler := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	exact := strings.Repeat("b", maxCorrelationLen)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(correlationHeader, exact)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(correlationHeader); got != exact {
		t.Errorf("id at exactly max length should be preserved, got %q", got)
	}
}

func TestRecover_PanicYields500EnvelopeNoStackInBody(t *testing.T) {
	var buf bytes.Buffer
	logger := testLogger(&buf)

	handler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not valid JSON: %v (%s)", err, rec.Body.String())
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in body, got %v", body)
	}
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("code = %v, want INTERNAL_ERROR", errObj["code"])
	}
	if strings.Contains(rec.Body.String(), "boom") || strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("response body must not contain panic value or stack trace: %s", rec.Body.String())
	}

	// The stack trace goes to the log, not the client.
	if !strings.Contains(buf.String(), "stack") {
		t.Errorf("expected stack trace logged, got %s", buf.String())
	}
}

func TestRecover_NoPanicPassesThrough(t *testing.T) {
	var buf bytes.Buffer
	logger := testLogger(&buf)

	handler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestAccessLog_ContainsCorrelationId(t *testing.T) {
	var buf bytes.Buffer
	logger := testLogger(&buf)

	inner := AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	handler := Correlation(inner)

	req := httptest.NewRequest(http.MethodPost, "/things", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("access log line not valid JSON: %v (%s)", err, buf.String())
	}
	for _, field := range []string{"method", "path", "status", "duration", "correlationId"} {
		if _, ok := line[field]; !ok {
			t.Errorf("access log missing field %q: %v", field, line)
		}
	}
	if line["method"] != http.MethodPost {
		t.Errorf("method = %v, want POST", line["method"])
	}
	if line["path"] != "/things" {
		t.Errorf("path = %v, want /things", line["path"])
	}
	if line["status"] != float64(http.StatusCreated) {
		t.Errorf("status = %v, want %d", line["status"], http.StatusCreated)
	}
}

// TestRecover_ErrAbortHandlerRePanicsSilently: http.ErrAbortHandler (a deliberate abort — the
// reverse proxy raises it when the client goes away) is re-raised for net/http to swallow, with
// no ERROR log and no second WriteHeader.
func TestRecover_ErrAbortHandlerRePanicsSilently(t *testing.T) {
	var buf bytes.Buffer
	handler := Recover(testLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	}))
	rec := httptest.NewRecorder()
	var got any
	func() {
		defer func() { got = recover() }()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	}()
	if got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want http.ErrAbortHandler re-raised", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the original 200 (no second WriteHeader)", rec.Code)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected nothing logged, got %s", buf.String())
	}
}

// TestWriteInternalError_CauseIsLoggedNotSent proves the 500 contract end to end through the
// middleware chain the services run (Correlation, AccessLog, then an inner StatusRecorder as
// the metrics middleware adds): the body is the code and a fixed message, and the cause is on
// the request's own access-log line, at error level, under the correlation id the client
// received.
func TestWriteInternalError_CauseIsLoggedNotSent(t *testing.T) {
	var buf bytes.Buffer
	logger := testLogger(&buf)

	handler := Correlation(AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner := &StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
		WriteInternalError(inner, errors.New("pq: relation \"secret_table\" does not exist"))
		if inner.Err == nil {
			t.Error("the inner recorder did not receive the cause")
		}
	})))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/things", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not valid JSON: %v (%s)", err, rec.Body.String())
	}
	if len(body.Error) != 2 || body.Error["code"] != "INTERNAL_ERROR" || body.Error["message"] != "internal error" {
		t.Fatalf("error = %v, want exactly code INTERNAL_ERROR and the fixed message", body.Error)
	}
	if strings.Contains(rec.Body.String(), "secret_table") {
		t.Fatalf("500 body carries the error text: %s", rec.Body.String())
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("access log line not valid JSON: %v (%s)", err, buf.String())
	}
	if line["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", line["level"])
	}
	if got, _ := line["error"].(string); !strings.Contains(got, "secret_table") {
		t.Errorf("access log error = %q, want the cause", got)
	}
	if id := rec.Header().Get("x-correlation-id"); id == "" || line["correlationId"] != id {
		t.Errorf("correlationId = %v, want the response header value %q", line["correlationId"], id)
	}
}

// TestAccessLog_NoErrorFieldWithoutACause: an ordinary response keeps the info-level line with
// no error field.
func TestAccessLog_NoErrorFieldWithoutACause(t *testing.T) {
	var buf bytes.Buffer
	handler := Correlation(AccessLog(testLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteInternalError(w, nil)
	})))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("access log line not valid JSON: %v (%s)", err, buf.String())
	}
	if _, ok := line["error"]; ok || line["level"] != "INFO" {
		t.Errorf("line = %v, want INFO without an error field", line)
	}
}
