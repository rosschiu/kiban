// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rosschiu/kiban/internal/audit"
)

// allowAllAuthorizer is a local test double that always allows — the shipped
// denyAllAuthorizer is untouched (this only exists to reach handleSetEnabled's
// past-the-guard branches: store errors, mandatory-disable 422, success).
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return true, nil
}

// closedPoolService builds a Service whose Store's pool is already closed — every query it
// issues fails deterministically at the connection level (no fragile timing race, no
// hand-edited migration state). Used only to reach the handlers' generic writeInternalError/500 branches.
func closedPoolService(t *testing.T, authz AdminAuthorizer) *Service {
	t.Helper()
	pool := registryPool(t)
	pool.Close()
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	return NewService(NewStore(pool), authz, auditWriter)
}

func TestHTTP_CapabilitiesAll_StoreError_500(t *testing.T) {
	svc := closedPoolService(t, NewDenyAllAuthorizer())
	req := httptest.NewRequest(http.MethodGet, "/api/platform/capabilities", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR envelope, got %v", body)
	}
}

func TestHTTP_CapabilityOne_StoreError_500(t *testing.T) {
	svc := closedPoolService(t, NewDenyAllAuthorizer())
	req := httptest.NewRequest(http.MethodGet, "/api/platform/capabilities/alpha", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Catalog_StoreError_500(t *testing.T) {
	svc := closedPoolService(t, NewDenyAllAuthorizer())
	req := httptest.NewRequest(http.MethodGet, "/api/platform/catalog", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Ready_StoreError_503(t *testing.T) {
	svc := closedPoolService(t, NewDenyAllAuthorizer())
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR envelope, got %v", body)
	}
}

// TestHTTP_Enable_AuthorizedButStoreFails_500 reaches handleSetEnabled's default (writeInternalError)
// switch branch: an allowed caller whose mutation fails for a reason OTHER than
// ErrModuleNotFound/ErrMandatoryModule. Uses the local allowAllAuthorizer test double (the
// shipped denyAllAuthorizer default is not touched by this or any other test) plus a closed pool
// so the underlying Begin() fails deterministically.
func TestHTTP_Enable_AuthorizedButStoreFails_500(t *testing.T) {
	svc := closedPoolService(t, allowAllAuthorizer{})
	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR envelope, got %v", body)
	}
}

// TestHTTP_Enable_AuthorizedNotFound_404 and TestHTTP_Disable_AuthorizedMandatory_422 exercise
// handleSetEnabled's other two switch branches over real HTTP (previously only reachable at the
// store layer directly, since denyAllAuthorizer always intercepts first).
func TestHTTP_Enable_AuthorizedNotFound_404(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)

	store := NewStore(registryPool(t))
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, allowAllAuthorizer{}, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/ghost/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND envelope, got %v", body)
	}
}

func TestHTTP_Disable_AuthorizedMandatory_422(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "spine", true)
	insertInstallationFixture(t, admin, "spine", true, true)

	store := NewStore(registryPool(t))
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, allowAllAuthorizer{}, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/spine/disable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", body)
	}
	if errObj["code"] != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", errObj["code"])
	}
	details, ok := errObj["details"].(map[string]any)
	if !ok || details["field"] != "key" {
		t.Errorf("details = %v, want field=key", errObj["details"])
	}
}

// TestHTTP_Enable_AuthorizedSuccess_200 proves the full success path (enable, real allow
// authorizer, real audit write, real HTTP envelope) end to end.
func TestHTTP_Enable_AuthorizedSuccess_200(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", true, false)

	store := NewStore(registryPool(t))
	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(store, allowAllAuthorizer{}, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	data, ok := body["data"].(map[string]any)
	if !ok || data["enabled"] != true {
		t.Errorf("data = %v, want enabled=true", body)
	}

	var count int
	if err := admin.QueryRow(context.Background(), `
		SELECT count(*) FROM audit.registry__events
		WHERE subject = 'module:alpha' AND action = 'platform.module.enable' AND actor = 'unauthenticated'
	`).Scan(&count); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if count != 1 {
		t.Errorf("audit rows = %d, want 1", count)
	}
}

// TestHTTP_Enable_DeniedAuditBeginFails proves auditDenial's own tx.Begin-error early return
// (a closed pool, so Begin fails before Record is ever reached) doesn't crash the 503 response
// path it's attached to.
func TestHTTP_Enable_DeniedAuditBeginFails(t *testing.T) {
	svc := closedPoolService(t, NewDenyAllAuthorizer())
	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}

// TestActorFor covers both of actorFor's branches directly. Only the empty-Subject branch is
// currently reachable through the HTTP layer (AuthContext.Subject is never populated by
// http.go's handleSetEnabled — see service.go's own doc comment); the non-empty branch is
// exercised as a direct unit call on the helper, same as this repo's other small pure-function
// helpers.
func TestActorFor(t *testing.T) {
	if got := actorFor(AuthContext{RawBearer: "Bearer " + unsignedBearerForActorTest(t, "kc-from-bearer")}); got != "kc-from-bearer" {
		t.Errorf("actorFor(bearer only) = %q, want kc-from-bearer", got)
	}
	if got := actorFor(AuthContext{RawBearer: "Bearer garbage"}); got != "unauthenticated" {
		t.Errorf("actorFor(garbage bearer) = %q, want unauthenticated", got)
	}
	if got := actorFor(AuthContext{}); got != "unauthenticated" {
		t.Errorf("actorFor(empty) = %q, want unauthenticated", got)
	}
	if got := actorFor(AuthContext{Subject: "user:42"}); got != "user:42" {
		t.Errorf("actorFor(Subject=user:42) = %q, want user:42", got)
	}
}

func TestAuthUnavailableError_Error(t *testing.T) {
	err := ErrAuthorizationUnavailable
	if err.Error() == "" {
		t.Fatal("Error() returned an empty string")
	}
	if !errors.Is(error(err), err) {
		t.Fatal("sentinel should be errors.Is-comparable with itself")
	}
}

func unsignedBearerForActorTest(t *testing.T, sub string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Subject(sub).Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestHTTP_Enable_NotInstalled_409 proves the not-installed HTTP mapping: an authorized enable of a module
// whose installation row has installed=false answers 409 MODULE_NOT_INSTALLED (the gateway's
// capability code) and leaves the row untouched.
func TestHTTP_Enable_NotInstalled_409(t *testing.T) {
	admin := adminPool(t)
	resetRegistryFixtures(t, admin)
	insertCatalogFixture(t, admin, "alpha", false)
	insertInstallationFixture(t, admin, "alpha", false, false)

	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		t.Fatalf("build audit writer: %v", err)
	}
	svc := NewService(NewStore(registryPool(t)), allowAllAuthorizer{}, auditWriter)
	req := httptest.NewRequest(http.MethodPost, "/internal/platform/modules/alpha/enable", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeEnvelope(t, rec)
	errObj, ok := body["error"].(map[string]any)
	if !ok || errObj["code"] != "MODULE_NOT_INSTALLED" {
		t.Errorf("expected MODULE_NOT_INSTALLED envelope, got %v", body)
	}
	cap, code, err := svc.store.Capability(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("capability lookup: %v", err)
	}
	if cap.Enabled || cap.Installed || code != "MODULE_NOT_INSTALLED" {
		t.Errorf("capability after refused enable = %+v code=%q, want not installed/not enabled", cap, code)
	}
}
