// SPDX-License-Identifier: Apache-2.0

package testsec

import (
	"net/http"
	"testing"
)

// Recorder wraps a real *http.ServeMux, recording every pattern registered through it (via
// Handle or HandleFunc) in registration order. A package's route-mounting function takes a
// small structural interface satisfied by both *http.ServeMux and *Recorder (Go interfaces are
// satisfied structurally — the production signature widens from *http.ServeMux to that
// interface with no change to its body), so a test can mount the SAME production code through a
// Recorder and get back the REAL registered-route list — not a hand-maintained parallel one that
// could silently drift from what the mount function actually does.
type Recorder struct {
	Mux        *http.ServeMux
	Registered []string
}

// NewRecorder builds a Recorder over a fresh *http.ServeMux.
func NewRecorder() *Recorder {
	return &Recorder{Mux: http.NewServeMux()}
}

// Handle records pattern and forwards to the underlying mux.
func (r *Recorder) Handle(pattern string, handler http.Handler) {
	r.Registered = append(r.Registered, pattern)
	r.Mux.Handle(pattern, handler)
}

// HandleFunc records pattern and forwards to the underlying mux.
func (r *Recorder) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	r.Registered = append(r.Registered, pattern)
	r.Mux.HandleFunc(pattern, handler)
}

// ServeHTTP delegates to the underlying mux, so a *Recorder can be used directly as the
// http.Handler under test.
func (r *Recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Mux.ServeHTTP(w, req)
}

// MissingSpecs returns every pattern in registered that has no exact match in wantPatterns —
// the pure comparison AssertNoDrift wraps. Exposed separately (rather than only as a *testing.T
// side effect) so a test can prove the drift pin actually fires without tripping its OWN
// t.Errorf/Fatalf: a failing subtest unconditionally marks every ancestor *testing.T as failed
// in Go's testing package (t.Run's bool return only reports whether the subtest passed — it
// does not undo that propagation), so "assert this check would fail" cannot be expressed by
// calling AssertNoDrift itself inside a throwaway subtest and inspecting the result.
func MissingSpecs(registered []string, wantPatterns []string) []string {
	want := make(map[string]bool, len(wantPatterns))
	for _, p := range wantPatterns {
		want[p] = true
	}
	var missing []string
	for _, p := range registered {
		if !want[p] {
			missing = append(missing, p)
		}
	}
	return missing
}

// AssertNoDrift fails t (via Errorf, one failure per offending route, so every gap is reported
// in one run rather than stopping at the first) if any pattern in registered has no exact match
// in wantPatterns — the drift pin: a route mounted through a Recorder-typed parameter without a
// corresponding RouteSpec in the package's matrix declaration fails this check.
func AssertNoDrift(t *testing.T, registered []string, wantPatterns []string) {
	t.Helper()
	for _, p := range MissingSpecs(registered, wantPatterns) {
		t.Errorf("route %q is registered but has no negative-security matrix entry — add a testsec.RouteSpec for it before this can land", p)
	}
}
