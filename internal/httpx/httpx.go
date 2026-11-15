// SPDX-License-Identifier: Apache-2.0

// Package httpx provides plumbing-only HTTP middleware shared across
// services: correlation-id propagation, panic recovery, and access
// logging. No auth/authz logic lives here.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/obs"
)

const (
	correlationHeader = "x-correlation-id"
	maxCorrelationLen = 128
	generatedIDNBytes = 16
)

// newCorrelationID generates a random hex-encoded correlation id.
func newCorrelationID() string {
	b := make([]byte, generatedIDNBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is effectively unrecoverable entropy
		// starvation; fall back to a fixed marker rather than panic.
		return "correlation-id-unavailable"
	}
	return hex.EncodeToString(b)
}

// Correlation reads the x-correlation-id request header (accepting values up
// to maxCorrelationLen characters; anything longer or absent is replaced
// with a freshly generated id), stores it in the request context, and
// echoes it on the response header.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(correlationHeader)
		if id == "" || len(id) > maxCorrelationLen {
			id = newCorrelationID()
		}
		ctx := obs.ContextWithCorrelation(r.Context(), id)
		w.Header().Set(correlationHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Recover returns middleware that catches panics in next, logs the stack
// (via logger, never the client), and writes a 500 INTERNAL_ERROR envelope.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						// A deliberate abort (httputil.ReverseProxy raises it when the client
						// goes away mid-body): headers are already sent, and net/http suppresses
						// this exact value — re-raise it untouched, no stack log, no second
						// WriteHeader.
						panic(rec)
					}
					l := obs.WithCorrelation(r.Context(), logger)
					l.Error("panic recovered",
						slog.Any("panic", rec),
						slog.String("stack", string(debug.Stack())),
					)
					errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{
						Code:    errenv.CodeInternalError,
						Message: "internal error",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// StatusRecorder captures the status code written by the wrapped handler.
//
// Embedding http.ResponseWriter alone satisfies the http.ResponseWriter interface, but SILENTLY
// DROPS every OPTIONAL interface the underlying ResponseWriter might also implement (http.Flusher
// for streaming/SSE, io.ReaderFrom for sendfile-style optimized copies). httputil.ReverseProxy —
// what the gateway wraps this recorder around for every module request — type-asserts the
// ResponseWriter it is given for http.Flusher directly, to stream the upstream response
// incrementally instead of buffering it whole (net/http/httputil/reverseproxy.go's own
// flush-interval logic). Flush() and ReadFrom() forward directly; Unwrap() opts into net/http's
// http.ResponseController "unwrap and retry" convention (net/http/responsecontroller.go), which
// is what makes Hijack/SetReadDeadline/SetWriteDeadline reach the real writer through this one.
type StatusRecorder struct {
	http.ResponseWriter
	Status int
	// Err is the cause WriteInternalError recorded for this response, if any. It is never
	// written to the client; AccessLog logs it on the request's own line.
	Err error
}

// RecordError keeps the cause of a 500 for the access log (see WriteInternalError).
func (s *StatusRecorder) RecordError(err error) {
	s.Err = err
}

func (s *StatusRecorder) WriteHeader(status int) {
	s.Status = status
	s.ResponseWriter.WriteHeader(status)
}

// Flush forwards to the wrapped ResponseWriter's http.Flusher, if it implements one — a no-op
// otherwise.
func (s *StatusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the wrapped ResponseWriter (the http.ResponseController convention).
func (s *StatusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// ReadFrom forwards to the wrapped ResponseWriter's io.ReaderFrom, if it implements one, falling
// back to an ordinary io.Copy otherwise.
func (s *StatusRecorder) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(s.ResponseWriter, r)
}

// AccessLog returns middleware that logs one line per request: method,
// path, status, duration, and correlationId (when present). A request answered through
// WriteInternalError is logged at error level with its cause.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
			next.ServeHTTP(rec, r)
			duration := time.Since(start)

			l := obs.WithCorrelation(r.Context(), logger)
			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.Status),
				slog.Duration("duration", duration),
			}
			if rec.Err != nil {
				// The cause of a 500 (WriteInternalError): logged here, never sent.
				l.Error("access", append(attrs, slog.String("error", rec.Err.Error()))...)
				return
			}
			l.Info("access", attrs...)
		})
	}
}

// Pinger is the readiness dependency Ready probes — *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Ready returns the GET /ready handler: 503 when the database ping fails, 200 otherwise.
func Ready(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
				Code:    errenv.CodeInternalError,
				Message: "database unavailable",
			})
			return
		}
		errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// WriteInternalError writes the 500 envelope: the stable code and a fixed message, nothing
// else. err is never included in the body (never leak internals to the client — mirrors
// Recover); it is handed to every StatusRecorder wrapped around w, so the AccessLog line of
// this request carries the cause next to the correlation id the client received in the
// x-correlation-id header.
func WriteInternalError(w http.ResponseWriter, err error) {
	recordError(w, err)
	errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{
		Code:    errenv.CodeInternalError,
		Message: "internal error",
	})
}

// recordError walks w's Unwrap chain (the http.ResponseController convention) and records err
// on every writer that accepts one.
func recordError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	for w != nil {
		if rec, ok := w.(interface{ RecordError(error) }); ok {
			rec.RecordError(err)
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}
