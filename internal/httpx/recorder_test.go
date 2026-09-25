// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// StatusRecorder used to embed http.ResponseWriter with no Flush()/Unwrap()/ReadFrom() of its
// own — httputil.ReverseProxy (what the gateway wraps this recorder around for every single
// module request) type-asserts the ResponseWriter it is given for http.Flusher directly, to
// stream a module's response incrementally instead of buffering it whole in memory. These are
// direct, deterministic unit proofs of the forwarding contract on the wrapper type itself.
func TestStatusRecorder_FlushForwardsToUnderlyingWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &StatusRecorder{ResponseWriter: rec, Status: http.StatusOK}

	s.Flush()

	if !rec.Flushed {
		t.Error("Flush() on StatusRecorder never reached the underlying httptest.ResponseRecorder")
	}
}

// F19: Unwrap() must return the exact underlying ResponseWriter, the contract
// http.ResponseController's own "unwrap and retry" convention (net/http/responsecontroller.go)
// depends on.
func TestStatusRecorder_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &StatusRecorder{ResponseWriter: rec, Status: http.StatusOK}
	if got := sr.Unwrap(); got != http.ResponseWriter(rec) {
		t.Errorf("Unwrap() = %v, want the exact underlying ResponseWriter %v", got, rec)
	}
}

// F19: ReadFrom must forward to the underlying writer's io.ReaderFrom when it implements one,
// and fall back to an ordinary io.Copy otherwise (httptest.ResponseRecorder implements neither
// specially, so it exercises the fallback path).
func TestStatusRecorder_ReadFrom(t *testing.T) {
	t.Run("forwards to underlying ReaderFrom", func(t *testing.T) {
		rf := &readerFromResponseWriter{ResponseRecorder: httptest.NewRecorder()}
		sr := &StatusRecorder{ResponseWriter: rf, Status: http.StatusOK}

		n, err := sr.ReadFrom(strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if n != 5 {
			t.Errorf("ReadFrom: n = %d, want 5", n)
		}
		if !rf.called {
			t.Error("ReadFrom did not forward to the underlying io.ReaderFrom")
		}
	})

	t.Run("falls back to io.Copy for a plain ResponseWriter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sr := &StatusRecorder{ResponseWriter: rec, Status: http.StatusOK}

		n, err := sr.ReadFrom(strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if n != 5 {
			t.Errorf("ReadFrom: n = %d, want 5", n)
		}
		if rec.Body.String() != "hello" {
			t.Errorf("rec.Body = %q, want %q", rec.Body.String(), "hello")
		}
	})
}

// readerFromResponseWriter is a minimal http.ResponseWriter that also implements io.ReaderFrom,
// so TestStatusRecorder_ReadFrom's "forwards" case can prove the forwarding branch (rather than
// the io.Copy fallback) actually ran.
type readerFromResponseWriter struct {
	*httptest.ResponseRecorder
	called bool
}

func (w *readerFromResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	w.called = true
	return io.Copy(w.ResponseRecorder, r)
}

type pingFunc func(context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestReady(t *testing.T) {
	serve := func(err error) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		Ready(pingFunc(func(context.Context) error { return err })).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		return rec
	}
	if rec := serve(nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("ready = %d %s, want 200 status ok", rec.Code, rec.Body.String())
	}
	if rec := serve(errors.New("down")); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "database unavailable") {
		t.Fatalf("not ready = %d %s, want 503 database unavailable", rec.Code, rec.Body.String())
	}
}

func TestWriteInternalError_NeverLeaksErr(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteInternalError(rec, errors.New("secret detail"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "secret detail") || !strings.Contains(body, `"INTERNAL_ERROR"`) {
		t.Fatalf("body = %s, want INTERNAL_ERROR envelope without the error text", body)
	}
}

func TestActorFor(t *testing.T) {
	if got := ActorFor("user:42", "Bearer "+unsignedToken(t, "kc-from-bearer")); got != "user:42" {
		t.Errorf("ActorFor(Subject=user:42) = %q, want user:42", got)
	}
	if got := ActorFor("", "Bearer "+unsignedToken(t, "kc-from-bearer")); got != "kc-from-bearer" {
		t.Errorf("ActorFor(bearer only) = %q, want kc-from-bearer", got)
	}
	if got := ActorFor("", "Bearer garbage"); got != "unauthenticated" {
		t.Errorf("ActorFor(garbage bearer) = %q, want unauthenticated", got)
	}
	if got := ActorFor("", ""); got != "unauthenticated" {
		t.Errorf("ActorFor(empty) = %q, want unauthenticated", got)
	}
}
