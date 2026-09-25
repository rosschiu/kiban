// SPDX-License-Identifier: Apache-2.0

// Package obs provides the platform's structured logger: a JSON slog
// handler to stderr with correlation-id awareness.
package obs

import (
	"context"
	"log/slog"
	"os"
)

type correlationKey struct{}

// New returns a JSON slog.Logger writing to stderr, tagged with the given
// service name. Every record carries "service", "time", "level", and "msg".
func New(service string) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stderr, nil)
	return slog.New(handler).With(slog.String("service", service))
}

// ContextWithCorrelation returns a context carrying the given correlation id.
func ContextWithCorrelation(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationKey{}, correlationID)
}

// CorrelationFromContext returns the correlation id stored in ctx, if any.
func CorrelationFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(correlationKey{}).(string)
	return v, ok && v != ""
}

// WithCorrelation returns logger enriched with a "correlationId" field when
// ctx carries one; otherwise it returns logger unchanged.
func WithCorrelation(ctx context.Context, logger *slog.Logger) *slog.Logger {
	if id, ok := CorrelationFromContext(ctx); ok {
		return logger.With(slog.String("correlationId", id))
	}
	return logger
}
