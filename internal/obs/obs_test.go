// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(buf *bytes.Buffer, service string) *slog.Logger {
	handler := slog.NewJSONHandler(buf, nil)
	return slog.New(handler).With(slog.String("service", service))
}

func TestNew_JSONWithServiceField(t *testing.T) {
	// New writes to stderr; verify shape via an equivalent handler wired to
	// a buffer, since New's target is fixed to os.Stderr by design.
	var buf bytes.Buffer
	logger := newTestLogger(&buf, "test-service")
	logger.Info("hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line not valid JSON: %v (%s)", err, buf.String())
	}
	for _, field := range []string{"service", "time", "level", "msg"} {
		if _, ok := rec[field]; !ok {
			t.Errorf("log record missing field %q: %v", field, rec)
		}
	}
	if rec["service"] != "test-service" {
		t.Errorf("service = %v, want test-service", rec["service"])
	}
}

func TestNew_ReturnsLogger(t *testing.T) {
	logger := New("svc")
	if logger == nil {
		t.Fatal("New returned nil")
	}
}

func TestWithCorrelation_AddsFieldWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, "svc")

	ctx := ContextWithCorrelation(context.Background(), "corr-123")
	WithCorrelation(ctx, logger).Info("event")

	if !strings.Contains(buf.String(), `"correlationId":"corr-123"`) {
		t.Errorf("expected correlationId in log line, got %s", buf.String())
	}
}

func TestWithCorrelation_NoFieldWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, "svc")

	WithCorrelation(context.Background(), logger).Info("event")

	if strings.Contains(buf.String(), "correlationId") {
		t.Errorf("expected no correlationId in log line, got %s", buf.String())
	}
}

func TestCorrelationFromContext(t *testing.T) {
	ctx := ContextWithCorrelation(context.Background(), "abc")
	got, ok := CorrelationFromContext(ctx)
	if !ok || got != "abc" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "abc")
	}

	_, ok = CorrelationFromContext(context.Background())
	if ok {
		t.Errorf("expected ok=false for context without correlation id")
	}
}
