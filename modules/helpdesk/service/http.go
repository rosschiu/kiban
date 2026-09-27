// SPDX-License-Identifier: Apache-2.0

// Package helpdesk implements the helpdesk module service: a ticket workflow (role tiers on the
// base company_module relations, assignment, status transitions, cross-module notification). Built solely against the platform's Go "SDK" packages (internal/errenv,
// internal/audit, internal/httpx, internal/obs, internal/config, modulekit) plus HTTP calls to org's
// company-facts API, authz's effective-access/grants API, and notification's targeted-events
// API — never by reaching into any foundation schema.
package helpdesk

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/modulekit"
)

// Service wires the helpdesk module's HTTP surface: bearer verification + per-operation authz
// decision. Two DIFFERENT authorization idioms are both exercised here, deliberately: (1) a
// company_module TIER check (member/agent/admin) via AuthzClient.Can for company-wide actions
// (create, work-all, manage/assign/agents), in contrast to docs's per-object tuples; (2) plain SERVICE-LOGIC row comparison for per-ticket visibility/transition
// eligibility (reporter_kcsub/assignee_kcsub against the caller) — there is no per-ticket engine
// call anywhere in this file, by design (no module object type, no per-ticket tuples).
type Service struct {
	Store        *Store
	Verifier     *modulekit.TokenVerifier
	Authz        *AuthzClient
	Org          *OrgClient
	Notification *NotificationClient
}

func NewService(store *Store, verifier *modulekit.TokenVerifier, authz *AuthzClient, org *OrgClient, notif *NotificationClient) *Service {
	return &Service{Store: store, Verifier: verifier, Authz: authz, Org: org, Notification: notif}
}

const (
	featureHelpdeskManage = "helpdesk.manage"
	featureTicketsWork    = "helpdesk.tickets.work"
	featureTicketsCreate  = "helpdesk.tickets.create"
)

func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	svc.mountRoutes(mux)
	return mux
}

func (svc *Service) mountRoutes(mux modulekit.MuxHandleFunc) {
	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", svc.handleReady)

	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/me", svc.withAuth(featureTicketsCreate, svc.handleMyTier))

	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/tickets", svc.withAuth(featureTicketsCreate, svc.handleListTickets))
	mux.HandleFunc("POST /api/helpdesk/v1/companies/{companyId}/tickets", svc.withAuth(featureTicketsCreate, svc.handleCreateTicket))
	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}", svc.withAuth(featureTicketsCreate, svc.handleGetTicket))
	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/audit", svc.withAuth(featureTicketsCreate, svc.handleGetTicketAudit))
	mux.HandleFunc("POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/assign", svc.withAuth(featureHelpdeskManage, svc.handleAssignTicket))
	mux.HandleFunc("POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/status", svc.withAuth(featureTicketsCreate, svc.handleTransitionStatus))

	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/comments", svc.withAuth(featureTicketsCreate, svc.handleListComments))
	mux.HandleFunc("POST /api/helpdesk/v1/companies/{companyId}/tickets/{ticketId}/comments", svc.withAuth(featureTicketsCreate, svc.handleCreateComment))

	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/assignable-positions", svc.withAuth(featureHelpdeskManage, svc.handleAssignablePositions))
	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/assignable-groups", svc.withAuth(featureHelpdeskManage, svc.handleAssignableGroups))
	mux.HandleFunc("GET /api/helpdesk/v1/companies/{companyId}/agents", svc.withAuth(featureHelpdeskManage, svc.handleListAgents))
	mux.HandleFunc("POST /api/helpdesk/v1/companies/{companyId}/agents", svc.withAuth(featureHelpdeskManage, svc.handleMakeAgent))
	mux.HandleFunc("DELETE /api/helpdesk/v1/companies/{companyId}/agents/positions/{positionId}", svc.withAuth(featureHelpdeskManage, svc.handleRemoveAgentForPosition))
	mux.HandleFunc("DELETE /api/helpdesk/v1/companies/{companyId}/agents/groups/{groupId}", svc.withAuth(featureHelpdeskManage, svc.handleRemoveAgentForGroup))
	mux.HandleFunc("DELETE /api/helpdesk/v1/companies/{companyId}/agents/{memberId}", svc.withAuth(featureHelpdeskManage, svc.handleRemoveAgent))
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
	CompanyID uuid.UUID
	TicketID  uuid.UUID // zero value for company-scoped-only routes
}

func (svc *Service) verifyBearer(w http.ResponseWriter, r *http.Request) (subject, rawBearer string, ok bool) {
	rawBearer = r.Header.Get("Authorization")
	bearer := modulekit.BearerFromHeader(rawBearer)
	subject, err := svc.Verifier.Verify(r.Context(), bearer)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{Code: errenv.CodeAuthTokenInvalid, Message: "invalid or missing bearer token"})
		return "", "", false
	}
	return subject, rawBearer, true
}

// withAuth gates a company-scoped, TIER-only route: helpdesk.tickets.create (membership-gated —
// "at least a plain member") or helpdesk.manage (company_module#admin). Every route mounts on
// featureTicketsCreate EXCEPT the admin-only assign/agents routes, which mount directly on
// featureHelpdeskManage. Per-ticket
// visibility/transition eligibility is a SEPARATE, additional check each handler performs itself
// against the ticket row (see the Service doc comment) — this gate only proves "at least a
// member" or "admin", never "may act on THIS ticket".
func (svc *Service) withAuth(featureKey string, next func(http.ResponseWriter, *http.Request, requestContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, rawBearer, ok := svc.verifyBearer(w, r)
		if !ok {
			return
		}
		companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
		if !ok {
			return
		}
		allowed, reason, err := svc.Authz.Can(r.Context(), rawBearer, featureKey, companyID.String())
		if err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
			return
		}
		if !allowed {
			errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "not authorized: " + reason})
			return
		}
		rc := requestContext{Subject: subject, RawBearer: rawBearer, CompanyID: companyID}
		if ticketIDStr := r.PathValue("ticketId"); ticketIDStr != "" {
			ticketID, ok := modulekit.ParsePathUUID(w, r, "ticketId")
			if !ok {
				return
			}
			rc.TicketID = ticketID
		}
		next(w, r, rc)
	}
}

// bearerFromHeader is referenced by this package's tests.
var bearerFromHeader = modulekit.BearerFromHeader

func writeStoreError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeValidationError, Message: verr.Message, Details: map[string]string{"field": verr.Field}})
	case errors.Is(err, ErrTicketNotFound), errors.Is(err, ErrAgentNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
	case errors.Is(err, ErrIdempotencyConflict):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
	default:
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
	}
}

// ---- tier -----------------------------------------------------------------------------------

// tier asks authz TWICE at most (manage, then work) to compute the caller's own company-wide
// helpdesk tier — "admin" > "agent" > "member". Two round trips, not one combined query, because
// that is exactly the shape AuthzClient.Can offers (modules never invent a
// combined-check endpoint of their own).
func (svc *Service) tier(r *http.Request, rc requestContext) (string, error) {
	if allowed, _, err := svc.Authz.Can(r.Context(), rc.RawBearer, featureHelpdeskManage, rc.CompanyID.String()); err != nil {
		return "", err
	} else if allowed {
		return "admin", nil
	}
	if allowed, _, err := svc.Authz.Can(r.Context(), rc.RawBearer, featureTicketsWork, rc.CompanyID.String()); err != nil {
		return "", err
	} else if allowed {
		return "agent", nil
	}
	return "member", nil
}

// canSeeTicket: reporter/agent/admin rules, PLUS the current holder of an assigned position OR a
// current member of an assigned group may view (holdership, or group membership, IS the
// visibility grant; they may also transition). isAssigneeViaEngine is pre-resolved by
// the caller (buildTicketWire/isAssigneeForTicket) via AuthzClient.IsPositionHolder/
// IsGroupMember — never re-derived here.
func canSeeTicket(tier string, t Ticket, subject string, isAssigneeViaEngine bool) bool {
	return tier == "agent" || tier == "admin" || t.ReporterKcSub == subject || isAssigneeViaEngine
}

// isAssigneeForTicket resolves the ONE authorization-relevant question a position- or
// group-assigned ticket adds: "does the caller currently hold this ticket's assigned position, or
// belong to its assigned group?" Returns false, nil (never an error) for a member-assigned or
// unassigned ticket — no round trip needed.
func (svc *Service) isAssigneeForTicket(r *http.Request, rc requestContext, t Ticket) (bool, error) {
	switch {
	case t.AssigneePositionID != nil:
		return svc.Authz.IsPositionHolder(r.Context(), rc.RawBearer, rc.CompanyID.String(), t.AssigneePositionID.String())
	case t.AssigneeGroupID != nil:
		return svc.Authz.IsGroupMember(r.Context(), rc.RawBearer, rc.CompanyID.String(), t.AssigneeGroupID.String())
	default:
		return false, nil
	}
}

// loadVisibleTicket is the shared read preamble: GetTicket → tier → isAssigneeForTicket →
// canSeeTicket. On failure the matching error response has already been written and ok is false;
// deniedMsg is the 403 message (routes differ only in that string).
func (svc *Service) loadVisibleTicket(w http.ResponseWriter, r *http.Request, rc requestContext, deniedMsg string) (t Ticket, tier string, isAssignee bool, ok bool) {
	t, err := svc.Store.GetTicket(r.Context(), rc.CompanyID, rc.TicketID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	tier, err = svc.tier(r, rc)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
		return
	}
	isAssignee, err = svc.isAssigneeForTicket(r, rc, t)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
		return
	}
	if !canSeeTicket(tier, t, rc.Subject, isAssignee) {
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: deniedMsg})
		return
	}
	return t, tier, isAssignee, true
}

// exactlyOne reports whether exactly one of vals is non-empty.
func exactlyOne(vals ...string) bool {
	n := 0
	for _, v := range vals {
		if v != "" {
			n++
		}
	}
	return n == 1
}

// ---- wire shapes ------------------------------------------------------------------------------

type ticketWire struct {
	ID                    string  `json:"id"`
	CompanyID             string  `json:"companyId"`
	Title                 string  `json:"title"`
	Description           string  `json:"description"`
	Status                string  `json:"status"`
	ReporterMemberID      string  `json:"reporterMemberId"`
	AssigneeMemberID      *string `json:"assigneeMemberId,omitempty"`
	AssigneeKind          string  `json:"assigneeKind,omitempty"` // "member" | "position" | "group" | "" (unassigned)
	AssigneePositionID    *string `json:"assigneePositionId,omitempty"`
	AssigneePositionTitle *string `json:"assigneePositionTitle,omitempty"`
	AssigneeGroupID       *string `json:"assigneeGroupId,omitempty"`
	AssigneeGroupTitle    *string `json:"assigneeGroupTitle,omitempty"`
	AssigneeDisplayName   *string `json:"assigneeDisplayName,omitempty"`
	MyTier                string  `json:"myTier,omitempty"`
	IsReporter            bool    `json:"isReporter"`
	IsAssignee            bool    `json:"isAssignee"`
	CreatedAt             string  `json:"createdAt"`
	UpdatedAt             string  `json:"updatedAt"`
}

const rfc3339 = "2006-01-02T15:04:05.999999999Z07:00"

// buildTicketWire converts a Ticket to its wire shape. Assignee identity is not a pure
// struct-copy for a position-assigned ticket — "is caller the assignee" and "who's the assignee's
// display name" both require a resolve-AT-READ round trip (AuthzClient.IsPositionHolder for the
// former — the ONLY authorization-relevant question; OrgClient.GetPositionHolder + GetMember for
// the latter — display only, never authoritative). Member-assigned tickets use a
// zero-round-trip IsAssignee comparison; only the display name needs one org lookup
// (assigneeDisplayName is resolved server-side because the browser has no non-superadmin
// positions route).
func (svc *Service) buildTicketWire(r *http.Request, rc requestContext, t Ticket, tier string) (ticketWire, error) {
	wire := ticketWire{
		ID: t.ID.String(), CompanyID: t.CompanyID.String(), Title: t.Title, Description: t.Description, Status: t.Status,
		ReporterMemberID: t.ReporterMemberID.String(), MyTier: tier, AssigneeKind: t.AssigneeKind(),
		IsReporter: t.ReporterKcSub == rc.Subject,
		CreatedAt:  t.CreatedAt.Format(rfc3339), UpdatedAt: t.UpdatedAt.Format(rfc3339),
	}

	switch t.AssigneeKind() {
	case BindingKindMember:
		s := t.AssigneeMemberID.String()
		wire.AssigneeMemberID = &s
		wire.IsAssignee = t.AssigneeKcSub != nil && *t.AssigneeKcSub == rc.Subject
		if member, err := svc.Org.GetMember(r.Context(), s); err == nil {
			name := member.DisplayName
			wire.AssigneeDisplayName = &name
		}
	case BindingKindPosition:
		posID := t.AssigneePositionID.String()
		wire.AssigneePositionID = &posID
		title := t.AssigneePositionTitle
		wire.AssigneePositionTitle = &title

		isHolder, err := svc.Authz.IsPositionHolder(r.Context(), rc.RawBearer, rc.CompanyID.String(), posID)
		if err != nil {
			return ticketWire{}, err
		}
		wire.IsAssignee = isHolder

		name := title
		if holderMemberID, ok, err := svc.Org.GetPositionHolder(r.Context(), posID); err == nil && ok {
			if holder, err := svc.Org.GetMember(r.Context(), holderMemberID); err == nil {
				name = title + " — held by " + holder.DisplayName
			}
		}
		wire.AssigneeDisplayName = &name
	case BindingKindGroup:
		groupID := t.AssigneeGroupID.String()
		wire.AssigneeGroupID = &groupID
		title := t.AssigneeGroupTitle
		wire.AssigneeGroupTitle = &title

		isMember, err := svc.Authz.IsGroupMember(r.Context(), rc.RawBearer, rc.CompanyID.String(), groupID)
		if err != nil {
			return ticketWire{}, err
		}
		wire.IsAssignee = isMember

		// A group has MULTIPLE members, not one holder — the display name names the group and its
		// current member count (org's own ListGroupMembers), never a single person's name.
		name := title
		if members, err := svc.Org.ListGroupMembers(r.Context(), groupID); err == nil {
			name = title + fmt.Sprintf(" (%d member(s))", len(members))
		}
		wire.AssigneeDisplayName = &name
	}
	return wire, nil
}

// ---- tickets ------------------------------------------------------------------------------------

func (svc *Service) handleMyTier(w http.ResponseWriter, r *http.Request, rc requestContext) {
	tier, err := svc.tier(r, rc)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"tier": tier})
}

type createTicketRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (svc *Service) handleCreateTicket(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req createTicketRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	memberID, isMember, _, err := svc.Org.MemberByKcSub(r.Context(), rc.CompanyID.String(), rc.Subject)
	if err != nil || !isMember || memberID == "" {
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "caller is not an active member of this company"})
		return
	}
	reporterMemberID, err := uuid.Parse(memberID)
	if err != nil {
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}
	status := http.StatusCreated
	if idempotencyKey != "" {
		if existing, existingHash, ok, err := svc.Store.FindTicketByIdempotencyKey(r.Context(), rc.CompanyID, rc.Subject, idempotencyKey); err != nil {
			errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
			return
		} else if ok {
			if existingHash != ticketIdempotencyPayloadHash(rc.CompanyID, rc.Subject, req.Title, req.Description) {
				errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
				return
			}
			wire, err := svc.buildTicketWire(r, rc, existing, "member")
			if err != nil {
				errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
				return
			}
			errenv.WriteData(w, http.StatusOK, wire)
			return
		}
	}
	t, err := svc.Store.CreateTicket(r.Context(), rc.Subject, rc.CompanyID, reporterMemberID, rc.Subject, req.Title, req.Description, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire, err := svc.buildTicketWire(r, rc, t, "member")
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, status, wire)
}

func (svc *Service) handleListTickets(w http.ResponseWriter, r *http.Request, rc requestContext) {
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "mine"
	}
	status := r.URL.Query().Get("status")

	tier, err := svc.tier(r, rc)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
		return
	}

	var reporterFilter string
	switch view {
	case "mine":
		reporterFilter = rc.Subject
	case "all":
		if tier == "member" {
			errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "view=all requires the agent or admin tier"})
			return
		}
	default:
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: `view must be "mine" or "all"`, Details: map[string]string{"field": "view"}})
		return
	}

	tickets, err := svc.Store.ListTickets(r.Context(), rc.CompanyID, reporterFilter, status)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]ticketWire, len(tickets))
	for i, t := range tickets {
		tw, err := svc.buildTicketWire(r, rc, t, tier)
		if err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
			return
		}
		wire[i] = tw
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

func (svc *Service) handleGetTicket(w http.ResponseWriter, r *http.Request, rc requestContext) {
	t, tier, _, ok := svc.loadVisibleTicket(w, r, rc, "not authorized to view this ticket")
	if !ok {
		return
	}
	wire, err := svc.buildTicketWire(r, rc, t, tier)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

type auditEventWire struct {
	OccurredAt string `json:"occurredAt"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	Subject    string `json:"subject"`
	Payload    any    `json:"payload"`
}

func toAuditEventWire(e AuditEvent) auditEventWire {
	return auditEventWire{OccurredAt: e.OccurredAt.Format(rfc3339), Actor: e.Actor, Action: e.Action, Subject: e.Subject, Payload: e.Payload}
}

// handleGetTicketAudit is the ticket detail page's status-timeline source, built from audit
// events — same visibility rule as handleGetTicket (reporter, agent, or admin).
func (svc *Service) handleGetTicketAudit(w http.ResponseWriter, r *http.Request, rc requestContext) {
	_, _, _, ok := svc.loadVisibleTicket(w, r, rc, "not authorized to view this ticket")
	if !ok {
		return
	}
	events, err := svc.Store.TicketAudit(r.Context(), rc.TicketID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]auditEventWire, len(events))
	for i, e := range events {
		wire[i] = toAuditEventWire(e)
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

type assignTicketRequest struct {
	AssigneeMemberID   string `json:"assigneeMemberId"`
	AssigneePositionID string `json:"assigneePositionId"`
	AssigneeGroupID    string `json:"assigneeGroupId"`
}

// handleAssignTicket: helpdesk.manage-gated (admin only, per the route mount). Accepts EXACTLY
// one of {assigneeMemberId, assigneePositionId, assigneeGroupId} (422 for
// zero-or-more-than-one). The member path auto-grants the agent tier for a non-agent (one fewer
// manual step; both are audited). The position/group paths NEVER
// auto-grant — the target must ALREADY be bound as a helpdesk agent (422 "position/group is not
// a helpdesk agent binding" otherwise), because auto-binding a chair/group to a tier as a side
// effect of assigning one ticket would be a silent grant.
func (svc *Service) handleAssignTicket(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req assignTicketRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	if !exactlyOne(req.AssigneeMemberID, req.AssigneePositionID, req.AssigneeGroupID) {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationFailed, Message: "exactly one of assigneeMemberId, assigneePositionId, or assigneeGroupId is required",
			Details: map[string]string{"field": "assigneeMemberId,assigneePositionId,assigneeGroupId"},
		})
		return
	}

	if _, err := svc.Store.GetTicket(r.Context(), rc.CompanyID, rc.TicketID); err != nil {
		writeStoreError(w, err)
		return
	}

	switch {
	case req.AssigneeMemberID != "":
		svc.assignTicketToMember(w, r, rc, req.AssigneeMemberID)
	case req.AssigneePositionID != "":
		svc.assignTicketToPosition(w, r, rc, req.AssigneePositionID)
	default:
		svc.assignTicketToGroup(w, r, rc, req.AssigneeGroupID)
	}
}

func (svc *Service) assignTicketToMember(w http.ResponseWriter, r *http.Request, rc requestContext, rawMemberID string) {
	assigneeMemberID, err := uuid.Parse(rawMemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "assigneeMemberId must be a valid UUID", Details: map[string]string{"field": "assigneeMemberId"}})
		return
	}

	member, err := svc.Org.GetMember(r.Context(), assigneeMemberID.String())
	if err != nil || member.KcSub == "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "assigneeMemberId has no linked user to assign to", Details: map[string]string{"field": "assigneeMemberId"}})
		return
	}

	correlationID := rc.TicketID.String() + ":" + assigneeMemberID.String()
	if _, err := svc.Store.GetAgent(r.Context(), rc.CompanyID, assigneeMemberID); errors.Is(err, ErrAgentNotFound) {
		if err := svc.Authz.GrantAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, correlationID+":auto-agent-grant"); err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant the agent tier"})
			return
		}
		if _, err := svc.Store.RecordAgent(r.Context(), rc.Subject, rc.CompanyID, assigneeMemberID, member.KcSub, rc.Subject); err != nil {
			writeStoreError(w, err)
			return
		}
	} else if err != nil {
		writeStoreError(w, err)
		return
	}

	t, err := svc.Store.AssignTicket(r.Context(), rc.Subject, rc.CompanyID, rc.TicketID, assigneeMemberID, member.KcSub)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	msg := "Ticket '" + t.Title + "' was assigned to you."
	_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, "Ticket assigned: "+t.Title, msg)

	wire, err := svc.buildTicketWire(r, rc, t, "admin")
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

// assignTicketToPosition: the position must ALREADY be bound as a helpdesk agent
// (svc.Store.GetAgentForPosition) — never auto-bound here, so assigning one ticket never silently
// binds a chair to a tier (422 otherwise).
// Notification resolves the position's CURRENT holder via org at send time (never snapshotted) —
// an unassigned chair is a legitimate, non-error no-op (OrgClient.GetPositionHolder's own
// contract).
func (svc *Service) assignTicketToPosition(w http.ResponseWriter, r *http.Request, rc requestContext, rawPositionID string) {
	positionID, err := uuid.Parse(rawPositionID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "assigneePositionId must be a valid UUID", Details: map[string]string{"field": "assigneePositionId"}})
		return
	}
	position, err := svc.Org.GetPosition(r.Context(), positionID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "assigneePositionId does not resolve to a real position", Details: map[string]string{"field": "assigneePositionId"}})
		return
	}
	if position.CompanyID != rc.CompanyID.String() {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "assigneePositionId must belong to this company", Details: map[string]string{"field": "assigneePositionId"}})
		return
	}
	if _, err := svc.Store.GetAgentForPosition(r.Context(), rc.CompanyID, positionID); errors.Is(err, ErrAgentNotFound) {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "position is not a helpdesk agent binding", Details: map[string]string{"field": "assigneePositionId"}})
		return
	} else if err != nil {
		writeStoreError(w, err)
		return
	}

	t, err := svc.Store.AssignTicketToPosition(r.Context(), rc.Subject, rc.CompanyID, rc.TicketID, positionID, position.Title)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	if holderMemberID, ok, err := svc.Org.GetPositionHolder(r.Context(), positionID.String()); err == nil && ok {
		if holder, err := svc.Org.GetMember(r.Context(), holderMemberID); err == nil && holder.KcSub != "" {
			msg := "Ticket '" + t.Title + "' was assigned to " + position.Title + ", which you hold."
			_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), holder.KcSub, "Ticket assigned: "+t.Title, msg)
		}
	}

	wire, err := svc.buildTicketWire(r, rc, t, "admin")
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

// assignTicketToGroup: the group must ALREADY be bound as a helpdesk agent
// (svc.Store.GetAgentForGroup) — never auto-bound here, same posture as assignTicketToPosition.
// Notification resolves the group's CURRENT members via org at send time (never snapshotted) and
// fans out to EVERY current member with a linked user — the one behavioral divergence from the
// position path's single-holder notification (a group has many members, not one holder). An
// empty/all-unlinked group is a legitimate, non-error no-op (zero SendEvent calls).
func (svc *Service) assignTicketToGroup(w http.ResponseWriter, r *http.Request, rc requestContext, rawGroupID string) {
	groupID, err := uuid.Parse(rawGroupID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "assigneeGroupId must be a valid UUID", Details: map[string]string{"field": "assigneeGroupId"}})
		return
	}
	group, err := svc.Org.GetGroup(r.Context(), groupID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "assigneeGroupId does not resolve to a real group", Details: map[string]string{"field": "assigneeGroupId"}})
		return
	}
	if group.CompanyID != rc.CompanyID.String() {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "assigneeGroupId must belong to this company", Details: map[string]string{"field": "assigneeGroupId"}})
		return
	}
	if _, err := svc.Store.GetAgentForGroup(r.Context(), rc.CompanyID, groupID); errors.Is(err, ErrAgentNotFound) {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "group is not a helpdesk agent binding", Details: map[string]string{"field": "assigneeGroupId"}})
		return
	} else if err != nil {
		writeStoreError(w, err)
		return
	}

	t, err := svc.Store.AssignTicketToGroup(r.Context(), rc.Subject, rc.CompanyID, rc.TicketID, groupID, group.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	svc.notifyGroupMembers(r, rc, groupID.String(), "Ticket '"+t.Title+"' was assigned to "+group.Name+", which you're a member of.", "Ticket assigned: "+t.Title)

	wire, err := svc.buildTicketWire(r, rc, t, "admin")
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

// notifyGroupMembers resolves groupID's CURRENT members via org (at send time, never snapshotted)
// and fans out one SendEvent per member with a linked user — non-fatal on any individual
// resolution/send failure (notification events are non-fatal on failure), so one bad lookup never blocks the rest of the fan-out.
func (svc *Service) notifyGroupMembers(r *http.Request, rc requestContext, groupID, message, subject string) {
	members, err := svc.Org.ListGroupMembers(r.Context(), groupID)
	if err != nil {
		return
	}
	for _, gm := range members {
		member, err := svc.Org.GetMember(r.Context(), gm.MemberID)
		if err != nil || member.KcSub == "" {
			continue
		}
		_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, subject, message)
	}
}

type transitionStatusRequest struct {
	Status string `json:"status"`
}

// validEdges is the ticket state machine, taken LITERALLY: open -> in_progress -> resolved ->
// closed, plus resolved -> open (reopen). No skip-ahead edges (e.g. open->resolved directly);
// where a transition rule is unclear, the stricter reading wins.
var validEdges = map[[2]string]bool{
	{StatusOpen, StatusInProgress}:     true,
	{StatusInProgress, StatusResolved}: true,
	{StatusResolved, StatusClosed}:     true,
	{StatusResolved, StatusOpen}:       true,
}

// canTransition applies the transition rules: the assignee or an admin may progress/resolve; the
// reporter may reopen a resolved ticket and may close their own resolved ticket; an admin may do
// anything except edit others' comments. Admin may trigger every valid
// edge regardless of assignment/reporter identity; assignee triggers the two forward-progress
// edges; reporter triggers the two resolved-exit edges, on their own ticket only.
// For a position- or group-assigned ticket, "assignee" means "the CURRENT holder of the assigned
// position" / "a CURRENT member of the assigned group" — isAssigneeViaEngine is pre-resolved by
// the caller via AuthzClient.IsPositionHolder/IsGroupMember (the assignee legs of
// canTransition apply to the position holder, and identically to group members).
func canTransition(t Ticket, subject, tier, from, to string, isAssigneeViaEngine bool) bool {
	if tier == "admin" {
		return true
	}
	isAssignee := (t.AssigneeKcSub != nil && *t.AssigneeKcSub == subject) || isAssigneeViaEngine
	isReporter := t.ReporterKcSub == subject
	switch [2]string{from, to} {
	case [2]string{StatusOpen, StatusInProgress}, [2]string{StatusInProgress, StatusResolved}:
		return isAssignee
	case [2]string{StatusResolved, StatusClosed}, [2]string{StatusResolved, StatusOpen}:
		return isReporter
	default:
		return false
	}
}

func (svc *Service) handleTransitionStatus(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req transitionStatusRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}

	t, tier, isAssignee, ok := svc.loadVisibleTicket(w, r, rc, "not authorized to view this ticket")
	if !ok {
		return
	}
	if !validEdges[[2]string{t.Status, req.Status}] {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "invalid status transition from " + t.Status + " to " + req.Status, Details: map[string]string{"field": "status"}})
		return
	}
	if !canTransition(t, rc.Subject, tier, t.Status, req.Status, isAssignee) {
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "not authorized to make this status transition"})
		return
	}

	updated, err := svc.Store.UpdateTicketStatus(r.Context(), rc.Subject, rc.CompanyID, rc.TicketID, t.Status, req.Status)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	if updated.ReporterKcSub != rc.Subject {
		msg := "Ticket '" + updated.Title + "' changed status: " + t.Status + " -> " + req.Status + "."
		_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), updated.ReporterKcSub, "Ticket status changed: "+updated.Title, msg)
	}

	wire, err := svc.buildTicketWire(r, rc, updated, tier)
	if err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not resolve assignee"})
		return
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

// ---- comments -----------------------------------------------------------------------------------

type commentWire struct {
	ID          string `json:"id"`
	TicketID    string `json:"ticketId"`
	AuthorKcSub string `json:"authorKcSub"`
	Body        string `json:"body"`
	CreatedAt   string `json:"createdAt"`
}

func toCommentWire(c Comment) commentWire {
	return commentWire{ID: c.ID.String(), TicketID: c.TicketID.String(), AuthorKcSub: c.AuthorKcSub, Body: c.Body, CreatedAt: c.CreatedAt.Format(rfc3339)}
}

func (svc *Service) handleListComments(w http.ResponseWriter, r *http.Request, rc requestContext) {
	_, _, _, ok := svc.loadVisibleTicket(w, r, rc, "not authorized to view this ticket")
	if !ok {
		return
	}
	comments, err := svc.Store.ListComments(r.Context(), rc.TicketID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]commentWire, len(comments))
	for i, c := range comments {
		wire[i] = toCommentWire(c)
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

type createCommentRequest struct {
	Body string `json:"body"`
}

// handleCreateComment: reporter/agent/admin on that ticket may comment (nobody edits comments —
// append-only). Fires a notification event: to the assignee when the REPORTER comments, to
// the reporter when anyone else (agent/admin) comments.
func (svc *Service) handleCreateComment(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req createCommentRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	t, _, _, ok := svc.loadVisibleTicket(w, r, rc, "not authorized to comment on this ticket")
	if !ok {
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}
	if idempotencyKey != "" {
		// Check for a replay/conflict BEFORE creating a new comment (and
		// before the notification fan-out below), so a replayed request never double-notifies.
		if existing, existingHash, ok, err := svc.Store.FindCommentByIdempotencyKey(r.Context(), rc.TicketID, rc.Subject, idempotencyKey); err != nil {
			errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
			return
		} else if ok {
			if existingHash != commentIdempotencyPayloadHash(rc.TicketID, rc.Subject, req.Body) {
				errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
				return
			}
			errenv.WriteData(w, http.StatusOK, toCommentWire(existing))
			return
		}
	}

	c, err := svc.Store.CreateComment(r.Context(), rc.Subject, rc.TicketID, req.Body, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	if rc.Subject == t.ReporterKcSub {
		// The assignee-notification leg resolves the CURRENT holder at send time for a
		// position-assigned ticket — never a snapshotted kcSub. An unassigned chair is a no-op,
		// not an error (OrgClient.GetPositionHolder's own contract).
		switch t.AssigneeKind() {
		case BindingKindMember:
			if t.AssigneeKcSub != nil && *t.AssigneeKcSub != "" {
				msg := "The reporter commented on ticket '" + t.Title + "'."
				_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), *t.AssigneeKcSub, "New comment: "+t.Title, msg)
			}
		case BindingKindPosition:
			if holderMemberID, ok, err := svc.Org.GetPositionHolder(r.Context(), t.AssigneePositionID.String()); err == nil && ok {
				if holder, err := svc.Org.GetMember(r.Context(), holderMemberID); err == nil && holder.KcSub != "" {
					msg := "The reporter commented on ticket '" + t.Title + "'."
					_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), holder.KcSub, "New comment: "+t.Title, msg)
				}
			}
		case BindingKindGroup:
			// The reporter-comment fan-out mirrors assignTicketToGroup's own — EVERY
			// current member with a linked user, resolved at send time.
			svc.notifyGroupMembers(r, rc, t.AssigneeGroupID.String(), "The reporter commented on ticket '"+t.Title+"'.", "New comment: "+t.Title)
		}
	} else {
		msg := "A new comment was added to your ticket '" + t.Title + "'."
		_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), t.ReporterKcSub, "New comment: "+t.Title, msg)
	}

	errenv.WriteData(w, http.StatusCreated, toCommentWire(c))
}

// ---- agents (helpdesk.manage — admin only) -------------------------------------------------------
//
// helpdesk.agent carries three binding shapes — a per-member row, a per-position row (the
// position's current holder holds the agent tier, so a successor inherits the position's access
// with zero permission edits on handover), or a per-group row. POST /agents accepts exactly one of
// {memberId, positionId, groupId}; GET /agents rows carry bindingKind so the UI can tell them
// apart; DELETE /agents/{memberId}, /agents/positions/{positionId} and /agents/groups/{groupId}
// are separate, unambiguous revoke routes — no overloading.

type agentWire struct {
	ID            string  `json:"id"`
	CompanyID     string  `json:"companyId"`
	BindingKind   string  `json:"bindingKind"` // "member" | "position" | "group"
	MemberID      *string `json:"memberId,omitempty"`
	PositionID    *string `json:"positionId,omitempty"`
	PositionTitle *string `json:"positionTitle,omitempty"`
	GroupID       *string `json:"groupId,omitempty"`
	GroupTitle    *string `json:"groupTitle,omitempty"`
	GrantedBy     string  `json:"grantedBy"`
	CreatedAt     string  `json:"createdAt"`
}

func toAgentWire(a Agent) agentWire {
	w := agentWire{
		ID: a.ID.String(), CompanyID: a.CompanyID.String(), BindingKind: a.BindingKind(),
		GrantedBy: a.GrantedBy, CreatedAt: a.CreatedAt.Format(rfc3339),
	}
	if a.MemberID != nil {
		id := a.MemberID.String()
		w.MemberID = &id
	}
	if a.PositionID != nil {
		id := a.PositionID.String()
		w.PositionID = &id
		title := a.PositionTitle
		w.PositionTitle = &title
	}
	if a.GroupID != nil {
		id := a.GroupID.String()
		w.GroupID = &id
		title := a.GroupTitle
		w.GroupTitle = &title
	}
	return w
}

// ---- assignable positions (the non-superadmin read) ---------------------------------------------
//
// GET .../assignable-positions is the module-owned read the assign sheet (and the
// agents-admin page's holder-name display) needs: the company's positions ALREADY bound as
// helpdesk agents (this module's own index — never the org chart at large, least disclosure),
// each with its CURRENT holder's displayName resolved via org S2S. helpdesk.manage-gated (any
// helpdesk admin, not just a platform superadmin), because org's own positions route is
// superadmin-only.

type assignablePositionWire struct {
	PositionID        string  `json:"positionId"`
	Title             string  `json:"title"`
	HolderMemberID    *string `json:"holderMemberId,omitempty"`
	HolderDisplayName *string `json:"holderDisplayName,omitempty"`
}

func (svc *Service) handleAssignablePositions(w http.ResponseWriter, r *http.Request, rc requestContext) {
	agents, err := svc.Store.ListAgents(r.Context(), rc.CompanyID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var wire []assignablePositionWire
	for _, a := range agents {
		if a.BindingKind() != BindingKindPosition {
			continue
		}
		row := assignablePositionWire{PositionID: a.PositionID.String(), Title: a.PositionTitle}
		if holderMemberID, ok, err := svc.Org.GetPositionHolder(r.Context(), a.PositionID.String()); err == nil && ok {
			row.HolderMemberID = &holderMemberID
			if holder, err := svc.Org.GetMember(r.Context(), holderMemberID); err == nil {
				name := holder.DisplayName
				row.HolderDisplayName = &name
			}
		}
		wire = append(wire, row)
	}
	if wire == nil {
		wire = []assignablePositionWire{}
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

// ---- assignable groups (the group sibling of assignable positions) ------------------------------
//
// GET .../assignable-groups is assignable-positions' group sibling: the company's groups ALREADY
// bound as helpdesk agents (this module's own index, least disclosure), each with its CURRENT
// member COUNT resolved via org S2S — a count, not a single holder name, since a group has many
// members rather than one chair.

type assignableGroupWire struct {
	GroupID     string `json:"groupId"`
	Title       string `json:"title"`
	MemberCount int    `json:"memberCount"`
}

func (svc *Service) handleAssignableGroups(w http.ResponseWriter, r *http.Request, rc requestContext) {
	agents, err := svc.Store.ListAgents(r.Context(), rc.CompanyID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var wire []assignableGroupWire
	for _, a := range agents {
		if a.BindingKind() != BindingKindGroup {
			continue
		}
		row := assignableGroupWire{GroupID: a.GroupID.String(), Title: a.GroupTitle}
		if members, err := svc.Org.ListGroupMembers(r.Context(), a.GroupID.String()); err == nil {
			row.MemberCount = len(members)
		}
		wire = append(wire, row)
	}
	if wire == nil {
		wire = []assignableGroupWire{}
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

func (svc *Service) handleListAgents(w http.ResponseWriter, r *http.Request, rc requestContext) {
	agents, err := svc.Store.ListAgents(r.Context(), rc.CompanyID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]agentWire, len(agents))
	for i, a := range agents {
		wire[i] = toAgentWire(a)
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

type makeAgentRequest struct {
	MemberID   string `json:"memberId"`
	PositionID string `json:"positionId"`
	GroupID    string `json:"groupId"`
}

// handleMakeAgent binds the agent tier to exactly one of {memberId, positionId, groupId} — zero
// or more than one is a 422. The member path grants in authz, then
// records. The position/group paths use the opposite ordering: index row first, tuple grant second; on grant failure
// the index row is deleted and 503 is returned — visible-but-powerless is never allowed to become
// powerful-but-invisible, so the compensating delete runs the OTHER direction from the member
// path's (grant-first) ordering.
func (svc *Service) handleMakeAgent(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req makeAgentRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	if !exactlyOne(req.MemberID, req.PositionID, req.GroupID) {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationFailed, Message: "exactly one of memberId, positionId, or groupId is required",
			Details: map[string]string{"field": "memberId,positionId,groupId"},
		})
		return
	}

	switch {
	case req.MemberID != "":
		svc.handleMakeMemberAgent(w, r, rc, req.MemberID)
	case req.PositionID != "":
		svc.handleMakePositionAgent(w, r, rc, req.PositionID)
	default:
		svc.handleMakeGroupAgent(w, r, rc, req.GroupID)
	}
}

func (svc *Service) handleMakeMemberAgent(w http.ResponseWriter, r *http.Request, rc requestContext, rawMemberID string) {
	memberID, err := uuid.Parse(rawMemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "memberId must be a valid UUID", Details: map[string]string{"field": "memberId"}})
		return
	}
	member, err := svc.Org.GetMember(r.Context(), memberID.String())
	if err != nil || member.KcSub == "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "memberId has no linked user to make an agent", Details: map[string]string{"field": "memberId"}})
		return
	}

	correlationID := rc.CompanyID.String() + ":" + memberID.String() + ":make-agent"
	if err := svc.Authz.GrantAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant the agent tier"})
		return
	}
	a, err := svc.Store.RecordAgent(r.Context(), rc.Subject, rc.CompanyID, memberID, member.KcSub, rc.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, toAgentWire(a))
}

func (svc *Service) handleMakePositionAgent(w http.ResponseWriter, r *http.Request, rc requestContext, rawPositionID string) {
	positionID, err := uuid.Parse(rawPositionID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "positionId must be a valid UUID", Details: map[string]string{"field": "positionId"}})
		return
	}
	position, err := svc.Org.GetPosition(r.Context(), positionID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "positionId does not resolve to a real position", Details: map[string]string{"field": "positionId"}})
		return
	}
	if position.CompanyID != rc.CompanyID.String() {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "positionId must belong to this company", Details: map[string]string{"field": "positionId"}})
		return
	}

	// Index row first (the position path's ordering).
	a, err := svc.Store.RecordAgentForPosition(r.Context(), rc.Subject, rc.CompanyID, positionID, position.Title, rc.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Tuple grant second: `company_module:<companyId>/helpdesk#editor @ position:<id>#holder`.
	correlationID := rc.CompanyID.String() + ":" + positionID.String() + ":make-position-agent"
	if err := svc.Authz.GrantPositionAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), positionID.String(), correlationID); err != nil {
		// Fail-safe direction: visible-but-powerless is never allowed to become
		// powerful-but-invisible — the index row must not survive a failed grant.
		_ = svc.Store.RemoveAgentForPosition(r.Context(), rc.Subject, rc.CompanyID, positionID)
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant the agent tier"})
		return
	}
	errenv.WriteData(w, http.StatusCreated, toAgentWire(a))
}

// handleMakeGroupAgent is handleMakePositionAgent's group sibling: same index-first-then-grant
// ordering and the same fail-safe compensating delete on grant failure.
func (svc *Service) handleMakeGroupAgent(w http.ResponseWriter, r *http.Request, rc requestContext, rawGroupID string) {
	groupID, err := uuid.Parse(rawGroupID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "groupId must be a valid UUID", Details: map[string]string{"field": "groupId"}})
		return
	}
	group, err := svc.Org.GetGroup(r.Context(), groupID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "groupId does not resolve to a real group", Details: map[string]string{"field": "groupId"}})
		return
	}
	if group.CompanyID != rc.CompanyID.String() {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "groupId must belong to this company", Details: map[string]string{"field": "groupId"}})
		return
	}

	// Index row first (the position/group path's ordering).
	a, err := svc.Store.RecordAgentForGroup(r.Context(), rc.Subject, rc.CompanyID, groupID, group.Name, rc.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Tuple grant second: `company_module:<companyId>/helpdesk#editor @ group:<id>#member`.
	correlationID := rc.CompanyID.String() + ":" + groupID.String() + ":make-group-agent"
	if err := svc.Authz.GrantGroupAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), groupID.String(), correlationID); err != nil {
		// Fail-safe direction: visible-but-powerless is never allowed to become
		// powerful-but-invisible — the index row must not survive a failed grant.
		_ = svc.Store.RemoveAgentForGroup(r.Context(), rc.Subject, rc.CompanyID, groupID)
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant the agent tier"})
		return
	}
	errenv.WriteData(w, http.StatusCreated, toAgentWire(a))
}

// handleRemoveAgent implements a last-admin-STYLE protection rule: refuse to remove the
// agent tier from a member currently assigned any non-closed ticket (reassign first). Admin-tier
// revocation is deliberately not offered here (no admin-tier grant/revoke surface) — this module only ever revokes the AGENT (editor) tier.
func (svc *Service) handleRemoveAgent(w http.ResponseWriter, r *http.Request, rc requestContext) {
	memberID, ok := modulekit.ParsePathUUID(w, r, "memberId")
	if !ok {
		return
	}

	member, err := svc.Org.GetMember(r.Context(), memberID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "member not found"})
		return
	}

	openCount, err := svc.Store.CountOpenAssignedTickets(r.Context(), rc.CompanyID, memberID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if openCount > 0 {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code:    errenv.CodeValidationFailed,
			Message: "this member is currently assigned open tickets — reassign them before removing the agent tier",
			Details: map[string]string{"field": "memberId", "openTicketCount": strconv.Itoa(openCount)},
		})
		return
	}

	correlationID := rc.CompanyID.String() + ":" + memberID.String() + ":remove-agent"
	if member.KcSub != "" {
		if err := svc.Authz.RevokeAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, correlationID); err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not revoke the agent tier"})
			return
		}
	}
	if err := svc.Store.RemoveAgent(r.Context(), rc.Subject, rc.CompanyID, memberID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveAgentForPosition revokes a position's agent-tier binding —
// `company_module:<companyId>/helpdesk#editor @ position:<id>#holder` — and its local index row.
// Because tickets can be assigned directly to a position, it applies the same protection as
// handleRemoveAgent — refuse while any open ticket is assigned directly to this
// position (reassign first).
func (svc *Service) handleRemoveAgentForPosition(w http.ResponseWriter, r *http.Request, rc requestContext) {
	positionID, ok := modulekit.ParsePathUUID(w, r, "positionId")
	if !ok {
		return
	}

	openCount, err := svc.Store.CountOpenAssignedTicketsForPosition(r.Context(), rc.CompanyID, positionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if openCount > 0 {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code:    errenv.CodeValidationFailed,
			Message: "this position is currently assigned open tickets — reassign them before removing the agent tier",
			Details: map[string]string{"field": "positionId", "openTicketCount": strconv.Itoa(openCount)},
		})
		return
	}

	correlationID := rc.CompanyID.String() + ":" + positionID.String() + ":remove-position-agent"
	if err := svc.Authz.RevokePositionAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), positionID.String(), correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not revoke the agent tier"})
		return
	}
	if err := svc.Store.RemoveAgentForPosition(r.Context(), rc.Subject, rc.CompanyID, positionID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveAgentForGroup is handleRemoveAgentForPosition's group sibling: revokes a group's
// agent-tier binding — `company_module:<companyId>/helpdesk#editor @ group:<id>#member` — and its
// local index row, refusing while any open ticket is assigned directly to this group (mirror of
// the position/member removal-protection rule).
func (svc *Service) handleRemoveAgentForGroup(w http.ResponseWriter, r *http.Request, rc requestContext) {
	groupID, ok := modulekit.ParsePathUUID(w, r, "groupId")
	if !ok {
		return
	}

	openCount, err := svc.Store.CountOpenAssignedTicketsForGroup(r.Context(), rc.CompanyID, groupID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if openCount > 0 {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code:    errenv.CodeValidationFailed,
			Message: "this group is currently assigned open tickets — reassign them before removing the agent tier",
			Details: map[string]string{"field": "groupId", "openTicketCount": strconv.Itoa(openCount)},
		})
		return
	}

	correlationID := rc.CompanyID.String() + ":" + groupID.String() + ":remove-group-agent"
	if err := svc.Authz.RevokeGroupAgent(r.Context(), rc.RawBearer, rc.CompanyID.String(), groupID.String(), correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not revoke the agent tier"})
		return
	}
	if err := svc.Store.RemoveAgentForGroup(r.Context(), rc.Subject, rc.CompanyID, groupID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
