// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMountDemoModeRoute_ReflectsFlag_NoAuthRequired proves the route's two contracts: the
// route answers exactly the configured DemoMode bool (never guessed from anything else), and it
// never requires a bearer — a logged-out visitor must see the banner before ever authenticating.
func TestMountDemoModeRoute_ReflectsFlag_NoAuthRequired(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		mux := http.NewServeMux()
		mountDemoModeRoute(mux, enabled)

		req := httptest.NewRequest(http.MethodGet, "/api/platform/demo-mode", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("enabled=%v: status = %d, want 200", enabled, rec.Code)
		}
		var body struct {
			Data struct {
				Enabled bool `json:"enabled"`
			} `json:"data"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.Data.Enabled != enabled {
			t.Errorf("data.enabled = %v, want %v", body.Data.Enabled, enabled)
		}
	}
}

// TestMountDemoModeRoute_DefaultOff proves the zero value (an un-set DemoMode field, matching
// cmd/gateway's own config default) answers false — every existing deployment that never
// touches KIBAN_DEMO_MODE gets no banner, with no extra wiring needed.
func TestMountDemoModeRoute_DefaultOff(t *testing.T) {
	mux := http.NewServeMux()
	var zeroValue bool
	mountDemoModeRoute(mux, zeroValue)

	req := httptest.NewRequest(http.MethodGet, "/api/platform/demo-mode", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `{"data":{"enabled":false}}`+"\n" {
		t.Errorf("body = %q, want the zero-value default false", got)
	}
}
