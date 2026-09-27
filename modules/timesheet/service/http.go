// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/modulekit"
)

// Service wires the timesheet module's HTTP surface: bearer verification + per-operation authz
// decision (same pattern as modules/notification/service/http.go, the CURRENT reference — see
// authzclient.go's header comment for what each featureKey's decision covers).
type Service struct {
	Store    *Store
	Verifier *modulekit.TokenVerifier
	Authz    *AuthzClient
	Org      *OrgClient
}

func NewService(store *Store, verifier *modulekit.TokenVerifier, authz *AuthzClient, org *OrgClient) *Service {
	return &Service{Store: store, Verifier: verifier, Authz: authz, Org: org}
}

const (
	featureProjectsManage     = "timesheet.projects.manage"
	featureConfigManage       = "timesheet.config.manage"
	featureApproversManage    = "timesheet.approvers.manage"
	featureSubmissionsSubmit  = "timesheet.submissions.submit"
	featureSubmissionsApprove = "timesheet.submissions.approve"
	featureEntriesManageOwn   = "timesheet.entries.manage-own"
)

func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	svc.mountRoutes(mux)
	return mux
}

func (svc *Service) mountRoutes(mux modulekit.MuxHandleFunc) {
	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", svc.handleReady)

	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/config", svc.withAuth(featureEntriesManageOwn, svc.handleGetConfig))
	mux.HandleFunc("PUT /api/timesheet/v1/companies/{companyId}/config", svc.withAuth(featureConfigManage, svc.handleUpdateConfig))

	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/projects", svc.withAuth(featureEntriesManageOwn, svc.handleListProjects))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/projects", svc.withAuth(featureProjectsManage, svc.handleCreateProject))
	mux.HandleFunc("PUT /api/timesheet/v1/companies/{companyId}/projects/{projectId}", svc.withAuth(featureProjectsManage, svc.handleUpdateProject))

	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/approvers", svc.withAuth(featureApproversManage, svc.handleListApprovers))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/approvers", svc.withAuth(featureApproversManage, svc.handleAssignApprover))

	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/entries", svc.withAuth(featureEntriesManageOwn, svc.handleListEntries))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/entries", svc.withAuth(featureEntriesManageOwn, svc.handleUpsertEntry))
	mux.HandleFunc("DELETE /api/timesheet/v1/companies/{companyId}/entries/{entryId}", svc.withAuth(featureEntriesManageOwn, svc.handleDeleteEntry))

	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/submissions", svc.withAuth(featureEntriesManageOwn, svc.handleListSubmissions))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/submissions", svc.withAuth(featureSubmissionsSubmit, svc.handleSubmitWeek))
	mux.HandleFunc("GET /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}", svc.withAuth(featureEntriesManageOwn, svc.handleGetSubmission))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}/approve", svc.withAuth(featureSubmissionsApprove, svc.handleApproveSubmission))
	mux.HandleFunc("POST /api/timesheet/v1/companies/{companyId}/submissions/{submissionId}/reject", svc.withAuth(featureSubmissionsApprove, svc.handleRejectSubmission))
}

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (svc *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	httpx.Ready(svc.Store.Pool())(w, r)
}

type requestContext struct {
	Subject   string
	RawBearer string
}

// withAuth validates the bearer and, for company-scoped routes, authorizes featureKey through
// authz's real effective-access decision — same shape/rationale as notification's http.go
// withAuth (see that file's header comment for the ordered-decision-steps explanation this
// mirrors verbatim).
func (svc *Service) withAuth(featureKey string, next func(http.ResponseWriter, *http.Request, requestContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawBearer := r.Header.Get("Authorization")
		bearer := modulekit.BearerFromHeader(rawBearer)
		subject, err := svc.Verifier.Verify(r.Context(), bearer)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{Code: errenv.CodeAuthTokenInvalid, Message: "invalid or missing bearer token"})
			return
		}

		companyID := r.PathValue("companyId")
		if companyID != "" {
			allowed, reason, err := svc.Authz.Can(r.Context(), rawBearer, featureKey, companyID)
			if err != nil {
				errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
				return
			}
			if !allowed {
				errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "not authorized: " + reason})
				return
			}
		}

		next(w, r, requestContext{Subject: subject, RawBearer: rawBearer})
	}
}

// bearerFromHeader is referenced by this package's tests.
var bearerFromHeader = modulekit.BearerFromHeader

// resolveCallerMember resolves the caller's own org member id in companyID (never client-
// supplied). Writes its own error response and returns
// ok=false on any failure, including "not an active member" (422, distinct from the 403 the
// authz decision already gave for company-membership-gated features).
func (svc *Service) resolveCallerMember(w http.ResponseWriter, r *http.Request, companyID, subject string) (uuid.UUID, bool) {
	memberID, isMember, isActive, err := svc.Org.MemberByKcSub(r.Context(), companyID, subject)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeInternalError, Message: "could not resolve org membership"})
		return uuid.UUID{}, false
	}
	if !isMember || !isActive {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "caller has no active member mapping in this company", Details: map[string]string{"field": "memberId"}})
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(memberID)
	if err != nil {
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "invalid member id from org"})
		return uuid.UUID{}, false
	}
	return id, true
}

func writeStoreError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: verr.Message, Details: map[string]string{"field": verr.Field}})
	case errors.Is(err, ErrProjectNotFound), errors.Is(err, ErrEntryNotFound), errors.Is(err, ErrSubmissionNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
	case errors.Is(err, ErrEntryNotDraft):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "entry is not editable (not draft)", Details: map[string]string{"field": "status"}})
	case errors.Is(err, ErrNoDraftEntries):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "no draft entries for that week", Details: map[string]string{"field": "weekStart"}})
	case errors.Is(err, ErrNoApproverAssigned):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "caller has no assigned approver", Details: map[string]string{"field": "approver"}})
	case errors.Is(err, ErrNotAssignedApprover):
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "caller is not the assigned approver for this submission"})
	case errors.Is(err, ErrSubmissionSuperseded):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "submission has been superseded by a newer version", Details: map[string]string{"field": "isCurrent"}})
	case errors.Is(err, ErrSubmissionNotSubmitted):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "submission is not awaiting a decision", Details: map[string]string{"field": "status"}})
	case errors.Is(err, ErrConflict):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeConflict, Message: "conflict"})
	case errors.Is(err, ErrIdempotencyConflict):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
	default:
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
	}
}

func parseWeekStart(w http.ResponseWriter, raw string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "weekStart must be YYYY-MM-DD", Details: map[string]string{"field": "weekStart"}})
		return time.Time{}, false
	}
	t = t.UTC()
	if !t.Equal(isoMonday(t)) {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: "weekStart must be an ISO Monday (UTC)", Details: map[string]string{"field": "weekStart"}})
		return time.Time{}, false
	}
	return t, true
}
