// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"github.com/rosschiu/kiban/internal/httpx"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/errenv"
)

// Routes builds the registry's HTTP handler (stdlib net/http, Go 1.22+ pattern routing).
// Callers wrap it with the shared httpx middleware (Correlation, Recover, AccessLog).
func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public-read: deliberately outside any admin gate (avoids the gateway<->auth authorization
	// cycle).
	mux.HandleFunc("GET /api/platform/capabilities", svc.handleCapabilitiesAll)
	mux.HandleFunc("GET /api/platform/capabilities/{module}", svc.handleCapabilityOne)
	mux.HandleFunc("GET /api/platform/catalog", svc.handleCatalog)

	// Mutations: guarded by AdminAuthorizer.
	mux.HandleFunc("POST /internal/platform/modules/{key}/enable", svc.handleSetEnabled(true))
	mux.HandleFunc("POST /internal/platform/modules/{key}/disable", svc.handleSetEnabled(false))

	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", httpx.Ready(svc.store.Pool()))

	return mux
}

func (svc *Service) handleCapabilitiesAll(w http.ResponseWriter, r *http.Request) {
	entries, err := svc.store.Catalog(r.Context())
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	caps := make([]Capability, 0, len(entries))
	for _, e := range entries {
		oneCap, _, err := svc.store.Capability(r.Context(), e.ModuleKey)
		if err != nil {
			httpx.WriteInternalError(w, err)
			return
		}
		caps = append(caps, oneCap)
	}
	errenv.WriteData(w, http.StatusOK, caps)
}

func (svc *Service) handleCapabilityOne(w http.ResponseWriter, r *http.Request) {
	moduleKey := r.PathValue("module")
	oneCap, _, err := svc.store.Capability(r.Context(), moduleKey)
	if err != nil {
		if errors.Is(err, ErrModuleNotFound) {
			errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
				Code:    errenv.CodeNotFound,
				Message: "module not found in the registry catalog",
			})
			return
		}
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, oneCap)
}

func (svc *Service) handleCatalog(w http.ResponseWriter, r *http.Request) {
	entries, err := svc.store.Catalog(r.Context())
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, entries)
}

// authorize is the shared fail-closed gate for AdminAuthorizer-guarded mutations — same order as
// org/identity: guard first, audit the denial (with authz's real reason for a confirmed denial →
// 403; AUTHORIZATION_UNAVAILABLE when no definite answer was reached → 503), only then touch
// the store.
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

// handleSetEnabled returns the enable (enabled=true) or disable (enabled=false) handler.
// Order: authorization guard (fail-closed 503) -> validation/mutation
// (transactional, audited in the same transaction) -> denial audit (its own transaction, since
// no state change occurred to attach to).
func (svc *Service) handleSetEnabled(enabled bool) http.HandlerFunc {
	action := "platform.module.enable"
	if !enabled {
		action = "platform.module.disable"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		moduleKey := r.PathValue("key")
		// RawBearer: forwarded verbatim from the inbound request (never a body value);
		// EffectiveAccessAuthorizer reads it. Subject stays empty — no independent bearer verification happens
		// in THIS handler (the gateway already verified the JWT; this only forwards its raw
		// header on to authz for registry's own confirmation, see adminauthz.go).
		authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}

		if !svc.authorize(w, r, authCtx, action, "module:"+moduleKey) {
			return
		}

		_, err := svc.store.SetEnabled(r.Context(), moduleKey, enabled, func(ctx context.Context, tx pgx.Tx) error {
			return svc.audit.Record(ctx, tx, audit.Event{
				Actor:   actorFor(authCtx),
				Action:  action,
				Subject: "module:" + moduleKey,
				Payload: map[string]any{"enabled": enabled},
			})
		})
		if err != nil {
			switch {
			case errors.Is(err, ErrModuleNotFound):
				errenv.WriteError(w, http.StatusNotFound, errenv.APIError{
					Code:    errenv.CodeNotFound,
					Message: "module not found in the registry catalog",
				})
			case errors.Is(err, ErrModuleNotInstalled):
				errenv.WriteError(w, http.StatusConflict, errenv.APIError{
					Code:    errenv.CodeModuleNotInstalled,
					Message: "module is not installed; install it before enabling",
				})
			case errors.Is(err, ErrMandatoryModule):
				errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
					Code:    errenv.CodeValidationError,
					Message: "a mandatory module cannot be disabled",
					Details: map[string]string{"field": "key"},
				})
			default:
				httpx.WriteInternalError(w, err)
			}
			return
		}

		errenv.WriteData(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

func actorFor(authCtx AuthContext) string {
	return httpx.ActorFor(authCtx.Subject, authCtx.RawBearer)
}

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}
