// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/modulekit"
)

// Service wires the notification module's HTTP surface: bearer verification (own JWKS copy —
// backend modules verify the bearer themselves; JWT roles are never authority) + a per-operation
// authz effective-access decision (see authzclient.go's header comment and withAuth's own doc
// comment below for exactly what this checks and what it deliberately does NOT differentiate).
type Service struct {
	Store    *Store
	Verifier *modulekit.TokenVerifier
	Authz    *AuthzClient
	// Org is the membership-confirmation dependency (OrgClient, orgclient.go). May be
	// nil in tests that never exercise handleSendEvent — every other route is unaffected.
	Org MembershipChecker
}

func NewService(store *Store, verifier *modulekit.TokenVerifier, authz *AuthzClient) *Service {
	return &Service{Store: store, Verifier: verifier, Authz: authz}
}

// featureKey constants mirror authz.fragment.json's own features[].featureKey values exactly
// (feature keys are product-capability ids, never invented). Every company-scoped route below is
// mapped to the nearest declared capability; where the fragment doesn't declare one narrow enough
// (list/get channels, subscribe/unsubscribe), the closest existing key is used rather than
// inventing a new one.
const (
	featureChannelsManage = "notification.channels.manage" // create/delete a channel
	featureMessagesSend   = "notification.messages.send"   // send a message
	featureInboxView      = "notification.inbox.view"      // list/get channels, subscribe/unsubscribe, read inbox, mark read
)

func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	svc.mountRoutes(mux)
	return mux
}

func (svc *Service) mountRoutes(mux modulekit.MuxHandleFunc) {
	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", svc.handleReady)

	mux.HandleFunc("GET /api/notification/v1/companies/{companyId}/channels", svc.withAuth(featureInboxView, svc.handleListChannels))
	mux.HandleFunc("POST /api/notification/v1/companies/{companyId}/channels", svc.withAuth(featureChannelsManage, svc.handleCreateChannel))
	mux.HandleFunc("GET /api/notification/v1/companies/{companyId}/channels/{channelId}", svc.withAuth(featureInboxView, svc.handleGetChannel))
	mux.HandleFunc("DELETE /api/notification/v1/companies/{companyId}/channels/{channelId}", svc.withAuth(featureChannelsManage, svc.handleDeleteChannel))
	mux.HandleFunc("POST /api/notification/v1/companies/{companyId}/channels/{channelId}/subscriptions", svc.withAuth(featureInboxView, svc.handleSubscribe))
	mux.HandleFunc("DELETE /api/notification/v1/companies/{companyId}/channels/{channelId}/subscriptions/me", svc.withAuth(featureInboxView, svc.handleUnsubscribe))
	mux.HandleFunc("GET /api/notification/v1/companies/{companyId}/messages", svc.withAuth(featureInboxView, svc.handleListInbox))
	mux.HandleFunc("POST /api/notification/v1/companies/{companyId}/messages", svc.withAuth(featureMessagesSend, svc.handleSendMessage))
	mux.HandleFunc("POST /api/notification/v1/companies/{companyId}/messages/{messageId}/read", svc.withAuth(featureInboxView, svc.handleMarkRead))

	// The S2S targeted-events entry point — deliberately mounted under `/internal/`,
	// NOT `/api/notification/...`, so it is never routed by the gateway. The gateway's
	// module proxy only ever forwards inbound paths that already start with `/api/{moduleKey}`
	// (internal/gateway/proxy.go's Rewrite touches only scheme/host, the path is the ORIGINAL
	// inbound request's — never rejoined), so a path starting `/internal/` can structurally never
	// reach here through it; TestSendEvent_UnreachableThroughModuleProxyPathShape proves this.
	mux.HandleFunc("POST /internal/notification/v1/companies/{companyId}/events", svc.handleSendEvent)
}

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (svc *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	httpx.Ready(svc.Store.Pool())(w, r)
}

// requestContext carries the bearer subject through a request — attached by withAuth.
type requestContext struct {
	Subject   string
	RawBearer string // the verified Authorization header, forwarded verbatim to authz grants
}

// withAuth validates the bearer (never accept an inbound x-user-* header as identity — this
// module never even looks at one; the ONLY identity source is the bearer this handler verifies
// itself) and, for company-scoped routes, authorizes featureKey through authz's real
// effective-access decision — AUTHORIZATION_DENIED (403) on an explicit deny,
// AUTHORIZATION_UNAVAILABLE (503) fail-closed on anything else (never treat "couldn't check" as
// "allowed").
//
// What this decision covers: the ordered steps 1-6 (subject found, Keycloak enabled, lifecycle
// active, company active, active membership, notification module enabled) for every
// company-scoped route, PLUS step 7's object-relation leg (company_module#admin) for
// `channels.manage`/`messages.send` — a plain active member is correctly denied those two,
// non-members are denied everything, and the platform superadmin resolves `company_module#admin`
// via the base model's `tupleToUserset(system, superadmin)` branch against the
// `company_module:<companyId>/notification#system @ system:platform` structural tuple the
// default-grant writer puts in place for every (company, module) pair (default-ONCE:
// deliberately excluded pairs stay excluded, including for the superadmin — that exclusion is
// a product requirement). `inbox.view` (list/get channels, subscribe/unsubscribe, read inbox,
// mark read) carries NO relation leg — its fragment anchors on `company_module#member`, a
// relation the base model doesn't define — so it stays company-membership-gated only.
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

func writeStoreError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	var werr *WebhookPolicyError
	switch {
	case errors.As(err, &verr):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: verr.Message, Details: map[string]string{"field": verr.Field}})
	case errors.As(err, &werr):
		// A webhook target the SSRF policy rejects at CREATE time is
		// VALIDATION_FAILED, not the generic field-shape VALIDATION_ERROR — it's a domain-policy
		// rejection (the field itself is well-formed), and distinct callers may want to handle it
		// differently (e.g. surfacing the reason to an admin instead of a form field error).
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: werr.Message, Details: map[string]string{"field": "target"}})
	case errors.Is(err, ErrChannelNotFound), errors.Is(err, ErrMessageNotFound), errors.Is(err, ErrRecipientNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
	case errors.Is(err, ErrIdempotencyConflict):
		// Same Idempotency-Key, different payload (idempotency keys are payload-bound).
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
	case errors.Is(err, ErrConflict):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeConflict, Message: "conflict"})
	default:
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
	}
}

// ---- channel wire shapes + handlers --------------------------------------------------------

type channelWire struct {
	ID        string  `json:"id"`
	CompanyID string  `json:"companyId"`
	Key       string  `json:"key"`
	Label     string  `json:"label"`
	Kind      string  `json:"kind"`
	Target    *string `json:"target"`
	CreatedAt string  `json:"createdAt"`
}

func toChannelWire(c Channel) channelWire {
	return channelWire{
		ID: c.ID.String(), CompanyID: c.CompanyID.String(), Key: c.Key, Label: c.Label,
		Kind: c.Kind, Target: c.Target, CreatedAt: c.CreatedAt.Format(rfc3339),
	}
}

const rfc3339 = "2006-01-02T15:04:05.999999999Z07:00"

type createChannelRequest struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Kind   string  `json:"kind"`
	Target *string `json:"target"`
}

func (svc *Service) handleCreateChannel(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req createChannelRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	c, err := svc.Store.CreateChannel(r.Context(), rc.Subject, companyID, req.Key, req.Label, req.Kind, req.Target)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// The channel's company_module anchor (module contract §3): the decision layer binds any
	// notification_channel object check to the request's company through it. The store mints
	// the id, so the grant follows the commit; a failed grant answers 503 and leaves a channel
	// no object check can ever reach (no such check exists today — fail closed either way).
	if err := svc.Authz.GrantChannelAnchor(r.Context(), rc.RawBearer, companyID.String(), c.ID.String()); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not anchor channel"})
		return
	}
	errenv.WriteData(w, http.StatusCreated, toChannelWire(c))
}

func (svc *Service) handleListChannels(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	page, pageSize := modulekit.PageParams(r)
	items, total, err := svc.Store.ListChannels(r.Context(), companyID, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, items, total, page, pageSize, toChannelWire)
}

func (svc *Service) handleGetChannel(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	channelID, ok := modulekit.ParsePathUUID(w, r, "channelId")
	if !ok {
		return
	}
	c, err := svc.Store.GetChannel(r.Context(), companyID, channelID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toChannelWire(c))
}

func (svc *Service) handleDeleteChannel(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	channelID, ok := modulekit.ParsePathUUID(w, r, "channelId")
	if !ok {
		return
	}
	if err := svc.Store.DeleteChannel(r.Context(), rc.Subject, companyID, channelID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type subscribeRequest struct {
	Email *string `json:"email"`
}

func (svc *Service) handleSubscribe(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	channelID, ok := modulekit.ParsePathUUID(w, r, "channelId")
	if !ok {
		return
	}
	var req subscribeRequest
	if r.ContentLength != 0 {
		if !modulekit.DecodeJSON(w, r, &req) {
			return
		}
	}
	if err := svc.Store.Subscribe(r.Context(), rc.Subject, companyID, channelID, rc.Subject, req.Email); err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, map[string]string{"status": "subscribed"})
}

func (svc *Service) handleUnsubscribe(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	channelID, ok := modulekit.ParsePathUUID(w, r, "channelId")
	if !ok {
		return
	}
	if err := svc.Store.Unsubscribe(r.Context(), rc.Subject, companyID, channelID, rc.Subject); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- message wire shapes + handlers --------------------------------------------------------

type messageWire struct {
	ID          string  `json:"id"`
	CompanyID   string  `json:"companyId"`
	ChannelID   string  `json:"channelId"`
	SubjectLine string  `json:"subjectLine"`
	Body        string  `json:"body"`
	CreatedBy   string  `json:"createdBy"`
	CreatedAt   string  `json:"createdAt"`
	ReadAt      *string `json:"readAt"`
}

func toMessageWire(m Message) messageWire {
	var readAt *string
	if m.ReadAt != nil {
		s := m.ReadAt.Format(rfc3339)
		readAt = &s
	}
	return messageWire{
		ID: m.ID.String(), CompanyID: m.CompanyID.String(), ChannelID: m.ChannelID.String(),
		SubjectLine: m.SubjectLine, Body: m.Body, CreatedBy: m.CreatedBy,
		CreatedAt: m.CreatedAt.Format(rfc3339), ReadAt: readAt,
	}
}

type sendMessageRequest struct {
	ChannelID   string `json:"channelId"`
	SubjectLine string `json:"subjectLine"`
	Body        string `json:"body"`
}

func (svc *Service) handleSendMessage(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	var req sendMessageRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	channelID, err := uuid.Parse(req.ChannelID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "channelId must be a valid UUID", Details: map[string]string{"field": "channelId"}})
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}

	m, created, err := svc.Store.SendMessage(r.Context(), rc.Subject, companyID, channelID, req.SubjectLine, req.Body, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	errenv.WriteData(w, status, toMessageWire(m))
}

func (svc *Service) handleListInbox(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	page, pageSize := modulekit.PageParams(r)
	items, total, err := svc.Store.ListInbox(r.Context(), companyID, rc.Subject, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, items, total, page, pageSize, toMessageWire)
}

func (svc *Service) handleMarkRead(w http.ResponseWriter, r *http.Request, rc requestContext) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}
	messageID, ok := modulekit.ParsePathUUID(w, r, "messageId")
	if !ok {
		return
	}
	m, err := svc.Store.MarkRead(r.Context(), rc.Subject, companyID, messageID, rc.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, toMessageWire(m))
}

// ---- targeted events ------------------------------------------------------------------------

type sendEventRequest struct {
	RecipientKcSubs []string `json:"recipientKcSubs"`
	SubjectLine     string   `json:"subjectLine"`
	Body            string   `json:"body"`
	SourceModule    string   `json:"sourceModule"`
}

// handleSendEvent is `POST /internal/notification/v1/companies/{companyId}/events` — the S2S
// entry point another module (docs: "your doc was shared"; helpdesk: "ticket assigned to you")
// calls with the ACTING end user's own bearer forwarded verbatim (the platform's module->platform
// S2S pattern — same shape timesheet's own authzclient.go/orgclient.go use calling INTO this
// platform). Requires a valid bearer AND active company membership for the acting caller (reuses
// the SAME company-membership-only authz gate `inbox.view` already uses — no relation leg, no new
// featureKey invented); recipient kcSubs are checked independently via svc.Org (skipped, not
// error, if unconfirmed).
func (svc *Service) handleSendEvent(w http.ResponseWriter, r *http.Request) {
	companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
	if !ok {
		return
	}

	rawBearer := r.Header.Get("Authorization")
	bearer := modulekit.BearerFromHeader(rawBearer)
	subject, err := svc.Verifier.Verify(r.Context(), bearer)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{Code: errenv.CodeAuthTokenInvalid, Message: "invalid or missing bearer token"})
		return
	}

	allowed, reason, err := svc.Authz.Can(r.Context(), rawBearer, featureInboxView, companyID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
		return
	}
	if !allowed {
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "not authorized: " + reason})
		return
	}

	var req sendEventRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	if svc.Org == nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeInternalError, Message: "membership check unavailable"})
		return
	}

	sent, skipped, err := svc.Store.SendTargetedEvent(r.Context(), svc.Org, subject, companyID, req.SourceModule, req.SubjectLine, req.Body, req.RecipientKcSubs)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]any{"sent": sent, "skipped": skipped})
}
