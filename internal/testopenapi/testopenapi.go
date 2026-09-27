// SPDX-License-Identifier: Apache-2.0

// Package testopenapi is a reusable helper: load a module's openapi.yaml fragment once, then
// validate RECORDED handler-test responses (status + body) against the operation the request
// actually matched, so the running service is proven to honor its contract at the HTTP boundary.
//
// Library choice: github.com/getkin/kin-openapi (openapi3 + openapi3filter + routers/gorillamux).
// It is the most widely used, actively maintained pure-Go OpenAPI 3 implementation (used by
// Kubernetes-adjacent and many other production Go services), has no cgo/native dependency, and
// its openapi3filter sub-package already implements exactly the request/response validation
// needed here — no hand-rolled JSON Schema walker required. Footprint: one direct module
// (github.com/getkin/kin-openapi) plus its own small dependency tree (gorilla/mux for path
// routing, a YAML parser, a JSON Schema validator) — no other module in this repo touches any of
// them, so the added dependency surface is exactly one subtree, not a sprawl.
//
// Usage: Load a module's fragment once per test file (typically in a package-level var or a
// t.Helper() wrapper), then call ValidateResponse with the *http.Request actually driven through
// the handler and the *httptest.ResponseRecorder it produced — same request/response pair every
// existing handler test already builds, no parallel fixture needed.
package testopenapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// TB is the subset of testing.TB this package needs — lets callers pass a *testing.T without
// this package importing "testing" itself being a hard requirement for Load's own callers that
// don't need it (Load has no TB parameter; only the *testing.T-facing validation calls do).
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Spec is a loaded, validated openapi.yaml fragment plus its route matcher.
type Spec struct {
	doc    *openapi3.T
	router routers.Router
}

// Load reads and validates the OpenAPI document at path (a module's openapi.yaml), building the
// route matcher used by ValidateResponse. Fails fast (returns an error) on a malformed or
// internally-inconsistent fragment — the same class of error `make validate-modules`
// (cmd/modvalidate) already checks for its own OpenAPI rules, but this is kin-openapi's own OpenAPI
// 3 structural/schema validation, a different (complementary) check.
func Load(path string) (*Spec, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("testopenapi: load %s: %w", path, err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		return nil, fmt.Errorf("testopenapi: %s failed OpenAPI validation: %w", path, err)
	}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("testopenapi: build router for %s: %w", path, err)
	}
	return &Spec{doc: doc, router: router}, nil
}

// modulePath resolves modules/<name>/openapi.yaml relative to the REPO ROOT, computed from this
// source file's own location — so callers in any module's _test.go can use it the same way
// regardless of `go test`'s working directory.
func modulePath(module string) string {
	_, file, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(repoRoot, "modules", module, "openapi.yaml")
}

type loadResult struct {
	spec *Spec
	err  error
}

var (
	loadMu    sync.Mutex
	loadCache = map[string]loadResult{}
)

// LoadModule is Load(modulePath(module)), memoized per module name for the life of the test
// binary — every _test.go in a module's package can call this cheaply (e.g. once per test) with
// no repeated disk/parse cost.
func LoadModule(module string) (*Spec, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	if r, ok := loadCache[module]; ok {
		return r.spec, r.err
	}
	spec, err := Load(modulePath(module))
	loadCache[module] = loadResult{spec: spec, err: err}
	return spec, err
}

// ValidateResponse validates rec (the recorder a handler test already produced) against the
// operation req matches in the loaded spec — status code AND body schema. req must be the SAME
// request object passed to the handler (method, URL path, and any headers/body the routing or
// request-side schema might consult); rec must be the SAME recorder the handler wrote to.
//
// Fails the test (via tb.Fatalf) on: no matching operation for the request's method+path (the
// route itself is undocumented — a drift finding in its own right), an undeclared status code,
// or a response body that doesn't satisfy the declared schema (missing required field, wrong
// type, wrong nullability, etc. — exactly the drift class this helper exists to catch).
func (s *Spec) ValidateResponse(tb TB, req *http.Request, rec *httptest.ResponseRecorder) {
	tb.Helper()
	route, pathParams, err := s.router.FindRoute(req)
	if err != nil {
		tb.Fatalf("testopenapi: no documented operation matches %s %s: %v (route missing from openapi.yaml, or the fragment's servers/paths don't cover it)", req.Method, req.URL.Path, err)
		return
	}
	reqInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}
	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 rec.Code,
		Header:                 rec.Header(),
		// IncludeResponseStatus: an undeclared status code is exactly the "undocumented
		// status" drift class this helper exists to catch — kin-openapi's own default
		// (silently allow any undocumented status) would hide it.
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	respInput.SetBodyBytes(rec.Body.Bytes())
	if err := openapi3filter.ValidateResponse(context.Background(), respInput); err != nil {
		tb.Fatalf("testopenapi: response for %s %s (status %d) does not match openapi.yaml's declared schema: %v\nbody: %s",
			req.Method, req.URL.Path, rec.Code, err, rec.Body.String())
	}
}
