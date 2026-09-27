// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/httpx"
)

// Policy rules proven here: a confirmed authz denial is a 403 AUTHORIZATION_DENIED audited with
// authz's reason, distinct from the 503 fail-closed path; a per-user MFA override may
// only raise the requirement above the global policy; an unknown user id is a 404 on
// every user-scoped MFA route; and identity audit rows carry the request's correlation
// id).

// denyAuthorizer answers a confirmed denial with the given reason.
type denyAuthorizer struct{ reason string }

func (d denyAuthorizer) Can(ctx context.Context, authCtx AuthContext, action string) (bool, error) {
	return false, &DeniedError{Reason: d.reason}
}

func putJSON(t *testing.T, f *httpTestFixture, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	f.svc.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHTTP_Authorize_ConfirmedDenial_403AndAuditedWithReason(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, denyAuthorizer{reason: "PLATFORM_ROLE_REQUIRED"}, nil)
	admin := adminPool(t)

	rec := putJSON(t, f, "/internal/identity/mfa-policy/global", `{"required":true,"method":"otp"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
	if errObj["code"] != "AUTHORIZATION_DENIED" {
		t.Errorf("code = %v, want AUTHORIZATION_DENIED", errObj["code"])
	}
	if details, _ := errObj["details"].(map[string]any); details["reason"] != "PLATFORM_ROLE_REQUIRED" {
		t.Errorf("details = %v, want reason PLATFORM_ROLE_REQUIRED", errObj["details"])
	}

	var reason string
	err := admin.QueryRow(context.Background(), `
		SELECT payload->>'reason' FROM audit.identity__events
		WHERE action = 'identity.mfa_policy.set_global' AND payload->>'denied' = 'true'
	`).Scan(&reason)
	if err != nil {
		t.Fatalf("query denial audit row: %v", err)
	}
	if reason != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("audited reason = %q, want PLATFORM_ROLE_REQUIRED", reason)
	}

	// Fail-closed: the global policy is untouched.
	var required bool
	if err := admin.QueryRow(context.Background(), `SELECT required FROM identity.mfa_policy WHERE scope = 'global'`).Scan(&required); err != nil {
		t.Fatalf("read global policy: %v", err)
	}
	if required {
		t.Fatal("global policy was written despite the 403")
	}
}

// The 503 path still audits AUTHORIZATION_UNAVAILABLE as its reason (denyAllAuthorizer).
func TestHTTP_Authorize_Uncertain_503AuditedAsUnavailable(t *testing.T) {
	f := newHTTPTestFixture(t, nil)
	admin := adminPool(t)

	rec := putJSON(t, f, "/internal/identity/mfa-policy/global", `{"required":true,"method":"otp"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	var reason string
	err := admin.QueryRow(context.Background(), `
		SELECT payload->>'reason' FROM audit.identity__events WHERE action = 'identity.mfa_policy.set_global'
	`).Scan(&reason)
	if err != nil {
		t.Fatalf("query denial audit row: %v", err)
	}
	if reason != "AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("audited reason = %q, want AUTHORIZATION_UNAVAILABLE", reason)
	}
}

func TestHTTP_MfaPolicy_UserOverride_OnlyRaises(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	userID := resolveAndGetID(t, f, "kc-sub-only-raise")
	userPath := "/internal/identity/mfa-policy/users/" + userID.String()

	if rec := putJSON(t, f, "/internal/identity/mfa-policy/global", `{"required":true,"method":"otp"}`); rec.Code != http.StatusOK {
		t.Fatalf("set global otp: %d %s", rec.Code, rec.Body.String())
	}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"lower: required=false below a required global", `{"required":false}`, http.StatusUnprocessableEntity},
		{"equal: otp == otp", `{"required":true,"method":"otp"}`, http.StatusOK},
		{"raise: otp_or_passkey > otp", `{"required":true,"method":"otp_or_passkey"}`, http.StatusOK},
		{"raise: passkey > otp", `{"required":true,"method":"passkey"}`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := putJSON(t, f, userPath, c.body)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, c.want, rec.Body.String())
			}
			if c.want == http.StatusUnprocessableEntity {
				errObj := decodeEnvelope(t, rec)["error"].(map[string]any)
				if errObj["code"] != "VALIDATION_FAILED" {
					t.Errorf("code = %v, want VALIDATION_FAILED", errObj["code"])
				}
			}
		})
	}

	// Raise the global to passkey: otp_or_passkey is now below it.
	if rec := putJSON(t, f, "/internal/identity/mfa-policy/global", `{"required":true,"method":"passkey"}`); rec.Code != http.StatusOK {
		t.Fatalf("set global passkey: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putJSON(t, f, userPath, `{"required":true,"method":"otp_or_passkey"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("otp_or_passkey below a passkey global: status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	if rec := putJSON(t, f, userPath, `{"required":true,"method":"passkey"}`); rec.Code != http.StatusOK {
		t.Fatalf("passkey == passkey: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MfaPolicy_UnknownUser_404(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	path := "/internal/identity/mfa-policy/users/" + uuid.NewString()

	for _, c := range []struct {
		method, body string
	}{
		{http.MethodGet, ""},
		{http.MethodPut, `{"required":true,"method":"otp"}`},
		{http.MethodDelete, ""},
	} {
		req := httptest.NewRequest(c.method, path, bytes.NewReader([]byte(c.body)))
		rec := httptest.NewRecorder()
		f.svc.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404, body=%s", c.method, rec.Code, rec.Body.String())
			continue
		}
		if errObj := decodeEnvelope(t, rec)["error"].(map[string]any); errObj["code"] != "NOT_FOUND" {
			t.Errorf("%s: code = %v, want NOT_FOUND", c.method, errObj["code"])
		}
	}
}

// The mutation handlers pass the request context through, so the row's correlation_id is the
// id the httpx.Correlation middleware stored (or generated) for the request.
func TestHTTP_MfaPolicy_Mutation_AuditRowCarriesCorrelationID(t *testing.T) {
	f := newHTTPTestFixtureWithAuthz(t, allowAllAuthorizer{}, nil)
	admin := adminPool(t)

	req := httptest.NewRequest(http.MethodPut, "/internal/identity/mfa-policy/global", bytes.NewReader([]byte(`{"required":true,"method":"otp"}`)))
	req.Header.Set("x-correlation-id", "corr-identity-1")
	rec := httptest.NewRecorder()
	httpx.Correlation(f.svc.Routes()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var correlation *string
	err := admin.QueryRow(context.Background(), `
		SELECT correlation_id FROM audit.identity__events WHERE action = 'identity.mfa_policy.set_global'
	`).Scan(&correlation)
	if err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if correlation == nil || *correlation != "corr-identity-1" {
		got, _ := json.Marshal(correlation)
		t.Fatalf("correlation_id = %s, want corr-identity-1", got)
	}
}
