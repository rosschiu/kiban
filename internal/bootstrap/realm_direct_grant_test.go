// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// reconcileDirectGrantFlow's branch matrix against a fake admin API — converged,
// each repair step in isolation, and every admin-call error path.

type directGrantFake struct {
	flowExists   bool
	mfaPresent   bool
	mfaRequired  bool
	bound        bool
	failPath     string // a path substring whose request answers 500
	calls        []string
	realmPatched map[string]any
}

func (f *directGrantFake) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if f.failPath != "" && strings.Contains(r.Method+" "+r.URL.Path, f.failPath) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch {
		case r.URL.Path == "/admin/realms/kiban/authentication/flows" && r.Method == http.MethodGet:
			flows := []map[string]any{{"alias": builtinDirectGrantAlias}}
			if f.flowExists {
				flows = append(flows, map[string]any{"alias": directGrantFlowAlias})
			}
			writeJSON(w, flows)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/direct grant/copy":
			f.flowExists = true
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions" && r.Method == http.MethodGet:
			execs := []kcFlowExecutionRep{{ID: "u", Requirement: "REQUIRED", ProviderID: "direct-grant-validate-username"}}
			if f.mfaPresent {
				req := "DISABLED"
				if f.mfaRequired {
					req = "REQUIRED"
				}
				execs = append(execs, kcFlowExecutionRep{ID: "mfa-id", Requirement: req, ProviderID: mfaAuthenticatorID})
			}
			writeJSON(w, execs)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions/execution":
			f.mfaPresent = true
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions" && r.Method == http.MethodPut:
			f.mfaRequired = true
			w.WriteHeader(http.StatusAccepted)
		case r.URL.Path == "/admin/realms/kiban" && r.Method == http.MethodGet:
			flow := builtinDirectGrantAlias
			if f.bound {
				flow = directGrantFlowAlias
			}
			writeJSON(w, map[string]any{"directGrantFlow": flow})
		case r.URL.Path == "/admin/realms/kiban" && r.Method == http.MethodPut:
			f.bound = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestReconcileDirectGrantFlow(t *testing.T) {
	t.Run("converged: no writes", func(t *testing.T) {
		f := &directGrantFake{flowExists: true, mfaPresent: true, mfaRequired: true, bound: true}
		kc := fakeKCFor(t, "kiban", f.handler(t))
		changed, err := reconcileDirectGrantFlow(context.Background(), kc)
		if err != nil || changed {
			t.Fatalf("got (%v, %v), want (false, nil)", changed, err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "POST") || strings.HasPrefix(c, "PUT") {
				t.Errorf("unexpected write on a converged realm: %s", c)
			}
		}
	})

	t.Run("nothing present: copy, add, REQUIRED, bind — in that order", func(t *testing.T) {
		f := &directGrantFake{}
		kc := fakeKCFor(t, "kiban", f.handler(t))
		changed, err := reconcileDirectGrantFlow(context.Background(), kc)
		if err != nil || !changed {
			t.Fatalf("got (%v, %v), want (true, nil)", changed, err)
		}
		var writes []string
		for _, c := range f.calls {
			if strings.HasPrefix(c, "POST") || strings.HasPrefix(c, "PUT") {
				writes = append(writes, c)
			}
		}
		want := []string{
			"POST /admin/realms/kiban/authentication/flows/direct grant/copy",
			"POST /admin/realms/kiban/authentication/flows/kiban direct grant/executions/execution",
			"PUT /admin/realms/kiban/authentication/flows/kiban direct grant/executions",
			"PUT /admin/realms/kiban",
		}
		if strings.Join(writes, "\n") != strings.Join(want, "\n") {
			t.Fatalf("writes:\n%s\nwant:\n%s", strings.Join(writes, "\n"), strings.Join(want, "\n"))
		}
		if !f.flowExists || !f.mfaPresent || !f.mfaRequired || !f.bound {
			t.Fatalf("fake state after repair = %+v, want everything converged", f)
		}
	})

	t.Run("execution present but DISABLED: only the requirement is set", func(t *testing.T) {
		f := &directGrantFake{flowExists: true, mfaPresent: true, bound: true}
		kc := fakeKCFor(t, "kiban", f.handler(t))
		changed, err := reconcileDirectGrantFlow(context.Background(), kc)
		if err != nil || !changed || !f.mfaRequired {
			t.Fatalf("got (%v, %v, required=%v), want (true, nil, true)", changed, err, f.mfaRequired)
		}
	})

	t.Run("flow wired but realm bound elsewhere: only the realm is patched", func(t *testing.T) {
		f := &directGrantFake{flowExists: true, mfaPresent: true, mfaRequired: true}
		kc := fakeKCFor(t, "kiban", f.handler(t))
		changed, err := reconcileDirectGrantFlow(context.Background(), kc)
		if err != nil || !changed || !f.bound {
			t.Fatalf("got (%v, %v, bound=%v), want (true, nil, true)", changed, err, f.bound)
		}
	})

	t.Run("authenticator still absent after adding it: an error", func(t *testing.T) {
		f := &directGrantFake{flowExists: true, bound: true}
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions/execution" {
				w.WriteHeader(http.StatusCreated) // "added", but the fake's listing never shows it
				return
			}
			f.handler(t)(w, r)
		})
		if _, err := reconcileDirectGrantFlow(context.Background(), kc); err == nil || !strings.Contains(err.Error(), "not present") {
			t.Fatalf("expected a not-present error, got %v", err)
		}
	})

	for _, failPath := range []string{
		"GET /admin/realms/kiban/authentication/flows",
		"POST /admin/realms/kiban/authentication/flows/direct grant/copy",
		"GET /admin/realms/kiban/authentication/flows/kiban direct grant/executions",
		"POST /admin/realms/kiban/authentication/flows/kiban direct grant/executions/execution",
		"PUT /admin/realms/kiban/authentication/flows/kiban direct grant/executions",
		"GET /admin/realms/kiban",
		"PUT /admin/realms/kiban",
	} {
		t.Run("error propagates: "+failPath, func(t *testing.T) {
			f := &directGrantFake{failPath: failPath}
			if strings.HasPrefix(failPath, "GET /admin/realms/kiban/authentication/flows/kiban") {
				f.flowExists = true
			}
			if failPath == "GET /admin/realms/kiban" || failPath == "PUT /admin/realms/kiban" {
				// The exact-path match below only fails the realm calls; flow calls run normally.
				f.flowExists, f.mfaPresent, f.mfaRequired = true, true, true
			}
			kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
				if r.Method+" "+r.URL.Path == failPath {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				f.failPath = ""
				f.handler(t)(w, r)
			})
			if _, err := reconcileDirectGrantFlow(context.Background(), kc); err == nil {
				t.Fatalf("expected an error when %s fails", failPath)
			}
		})
	}
}

// The re-read after adding the authenticator fails.
func TestReconcileDirectGrantFlow_RereadError(t *testing.T) {
	f := &directGrantFake{flowExists: true, bound: true}
	reads := 0
	kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/realms/kiban/authentication/flows/kiban direct grant/executions" && r.Method == http.MethodGet {
			reads++
			if reads == 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		f.handler(t)(w, r)
	})
	if _, err := reconcileDirectGrantFlow(context.Background(), kc); err == nil || !strings.Contains(err.Error(), "re-read") {
		t.Fatalf("expected a re-read error, got %v", err)
	}
}
