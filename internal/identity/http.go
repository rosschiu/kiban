// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rosschiu/kiban/internal/httpx"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/errenv"
)

// Routes builds the identity service's HTTP handler (stdlib net/http, Go 1.22+ pattern
// routing, same layout as registry). Callers wrap it with the shared httpx middleware
// (Correlation, Recover, AccessLog).
func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	// Bodyless self-sync: identity comes ONLY from the validated bearer — never a request body.
	mux.HandleFunc("POST /internal/identity/resolve", svc.handleResolve)

	// Effective-access step 2/3 input.
	mux.HandleFunc("GET /internal/identity/users/{kcSub}/state", svc.handleUserState)

	// The platform role is not identity's: its one record is authz's `system:platform#superadmin`
	// tuple, granted/revoked through authz's own /internal/authz/platform-roles routes.

	// MFA policy: reads are open (mirrors registry's public-read capability reads); writes and
	// sync are guarded by AdminAuthorizer (fail-closed denyAllAuthorizer when no real authorizer
	// is wired) — same pattern as registry's module enable/disable.
	mux.HandleFunc("GET /internal/identity/mfa-policy/global", svc.handleGetGlobalPolicy)
	mux.HandleFunc("PUT /internal/identity/mfa-policy/global", svc.handleSetGlobalPolicy)
	mux.HandleFunc("GET /internal/identity/mfa-policy/users/{userId}", svc.handleGetUserPolicy)
	mux.HandleFunc("PUT /internal/identity/mfa-policy/users/{userId}", svc.handleSetUserPolicy)
	mux.HandleFunc("DELETE /internal/identity/mfa-policy/users/{userId}", svc.handleClearUserPolicy)
	mux.HandleFunc("POST /internal/identity/mfa-policy/sync", svc.handleSyncPolicy)

	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", httpx.Ready(svc.store.Pool()))

	return mux
}

// bearerToken extracts the raw token from an "Authorization: Bearer <token>" header, "" if
// absent/malformed.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
}

// authenticate validates the request's bearer token and writes the appropriate 401 envelope on
// failure. Any caller-supplied x-user-* header on a protected route is rejected: identity
// comes only from the validated bearer, never from headers a caller controls.
func (svc *Service) authenticate(w http.ResponseWriter, r *http.Request) (Claims, bool) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-user-") {
			errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
				Code:    errenv.CodeBadRequest,
				Message: "caller-supplied identity headers are not allowed",
			})
			return Claims{}, false
		}
	}

	token := bearerToken(r)
	if token == "" {
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{
			Code:    errenv.CodeAuthTokenMissing,
			Message: "bearer token required",
		})
		return Claims{}, false
	}

	claims, err := svc.verifier.Verify(r.Context(), token)
	if err != nil {
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{
			Code:    errenv.CodeAuthTokenInvalid,
			Message: "bearer token invalid",
		})
		return Claims{}, false
	}
	return claims, true
}

func (svc *Service) handleResolve(w http.ResponseWriter, r *http.Request) {
	claims, ok := svc.authenticate(w, r)
	if !ok {
		return
	}
	user, err := svc.store.ResolveOrCreate(r.Context(), claims.Sub, claims.Email, claims.PreferredUsername)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, userView(user))
}

func (svc *Service) handleUserState(w http.ResponseWriter, r *http.Request) {
	kcSub := r.PathValue("kcSub")
	state, err := svc.store.ResolveUserState(r.Context(), svc.admin, kcSub)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
				Code:    errenv.CodeNotFound,
				Message: "user not found",
			})
			return
		}
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{
		"lifecycle": state.Lifecycle,
		"kcEnabled": state.KCEnabled,
	})
}

// authorize is the shared fail-closed gate for AdminAuthorizer-guarded mutations (MFA policy
// writes/sync) — same order as registry's handleSetEnabled: guard first, audit the denial
// (with authz's real reason for a confirmed denial → 403; AUTHORIZATION_UNAVAILABLE when no
// definite answer was reached → 503), only then touch the store.
func (svc *Service) authorize(w http.ResponseWriter, r *http.Request, authCtx AuthContext, action, subject string) bool {
	ok, err := svc.authz.Can(r.Context(), authCtx, action)
	if ok && err == nil {
		return true
	}
	var denied *DeniedError
	if errors.As(err, &denied) {
		audit.Denial(r.Context(), svc.store.pool, svc.audit, actorFor(authCtx), action, subject, denied.Reason)
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{
			Code:    errenv.CodeAuthorizationDenied,
			Message: "authorization denied: " + denied.Reason,
			Details: map[string]string{"reason": denied.Reason},
		})
		return false
	}
	audit.Denial(r.Context(), svc.store.pool, svc.audit, actorFor(authCtx), action, subject, errenv.CodeAuthorizationUnavailable)
	errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
		Code:    errenv.CodeAuthorizationUnavailable,
		Message: "authorization is unavailable",
	})
	return false
}

func actorFor(authCtx AuthContext) string {
	return httpx.ActorFor(authCtx.Subject, authCtx.RawBearer)
}

func parseUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code:    errenv.CodeBadRequest,
			Message: "invalid user id",
			Details: map[string]string{"field": "userId"},
		})
		return uuid.UUID{}, false
	}
	return id, true
}

func (svc *Service) handleGetGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := svc.store.GetGlobalPolicy(r.Context())
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, policyView(policy))
}

type setPolicyRequest struct {
	Required bool   `json:"required"`
	Method   string `json:"method"`
}

func (svc *Service) handleSetGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "identity.mfa_policy.set_global", "mfa_policy:global") {
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid request body"})
		return
	}

	err := svc.store.SetGlobalPolicy(r.Context(), req.Required, req.Method, func(ctx context.Context, tx pgx.Tx) error {
		return svc.audit.Record(ctx, tx, audit.Event{
			Actor: actorFor(authCtx), Action: "identity.mfa_policy.set_global", Subject: "mfa_policy:global",
			Payload: map[string]any{"required": req.Required, "method": req.Method},
		})
	})
	if err != nil {
		writeMfaPolicyError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]bool{"required": req.Required})
}

// writeMfaPolicyError maps the MFA-policy store errors: write-time validation (an
// unenforceable method, a user override weaker than the global policy) → 422
// VALIDATION_FAILED; an unknown user id → 404; anything else is an internal error, same as
// every other mutation handler in this file.
func writeMfaPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrMfaMethodUnenforceable):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code:    errenv.CodeValidationFailed,
			Message: err.Error(),
			Details: map[string]string{"field": "method"},
		})
	case errors.Is(err, ErrMfaPolicyWeakerThanGlobal):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code:    errenv.CodeValidationFailed,
			Message: err.Error(),
			Details: map[string]string{"field": "required"},
		})
	case errors.Is(err, ErrUserNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
			Code:    errenv.CodeNotFound,
			Message: "user not found",
		})
	default:
		httpx.WriteInternalError(w, err)
	}
}

func (svc *Service) handleGetUserPolicy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}
	policy, err := svc.store.EffectivePolicy(r.Context(), userID)
	if err != nil {
		writeMfaPolicyError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, policyView(policy))
}

func (svc *Service) handleSetUserPolicy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "identity.mfa_policy.set_user", "user:"+userID.String()) {
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid request body"})
		return
	}

	err := svc.store.SetUserPolicy(r.Context(), userID, req.Required, req.Method, func(ctx context.Context, tx pgx.Tx) error {
		return svc.audit.Record(ctx, tx, audit.Event{
			Actor: actorFor(authCtx), Action: "identity.mfa_policy.set_user", Subject: "user:" + userID.String(),
			Payload: map[string]any{"required": req.Required, "method": req.Method},
		})
	})
	if err != nil {
		writeMfaPolicyError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]bool{"required": req.Required})
}

func (svc *Service) handleClearUserPolicy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "identity.mfa_policy.clear_user", "user:"+userID.String()) {
		return
	}

	err := svc.store.ClearUserPolicy(r.Context(), userID, func(ctx context.Context, tx pgx.Tx) error {
		return svc.audit.Record(ctx, tx, audit.Event{
			Actor: actorFor(authCtx), Action: "identity.mfa_policy.clear_user", Subject: "user:" + userID.String(),
		})
	})
	if err != nil {
		writeMfaPolicyError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"userId": userID.String()})
}

// recordPolicyAudit is a best-effort own-transaction audit write, used ONLY by
// handleSyncPolicy (the MFA policy write handlers above audit atomically via
// SetGlobalPolicy/SetUserPolicy/ClearUserPolicy's tx+auditRecord-callback shape). Sync is a
// per-user Keycloak write loop with no single transaction to
// audit inside, so it stays on this best-effort path.
func (svc *Service) recordPolicyAudit(ctx context.Context, authCtx AuthContext, action, subject string, payload any) {
	tx, err := svc.store.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	var p map[string]any
	if b, err := json.Marshal(payload); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if err := svc.audit.Record(ctx, tx, audit.Event{
		Actor: actorFor(authCtx), Action: action, Subject: subject, Payload: p,
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

func (svc *Service) handleSyncPolicy(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "identity.mfa_policy.sync", "mfa_policy:sync") {
		return
	}

	outcomes, err := svc.store.SyncMfaPolicy(r.Context(), svc.admin)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	svc.recordPolicyAudit(r.Context(), authCtx, "identity.mfa_policy.sync", "mfa_policy:sync", outcomes)
	errenv.WriteData(w, http.StatusOK, outcomes)
}

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func userView(u User) map[string]any {
	return map[string]any{
		"id":                u.ID.String(),
		"kcSub":             u.KcSub,
		"email":             u.Email,
		"preferredUsername": u.PreferredUsername,
		"lifecycle":         u.Lifecycle,
	}
}

func policyView(p MfaPolicy) map[string]any {
	return map[string]any{
		"required": p.Required,
		"method":   p.Method,
	}
}
