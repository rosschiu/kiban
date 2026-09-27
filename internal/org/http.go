// SPDX-License-Identifier: Apache-2.0

package org

import (
	"encoding/json"
	"errors"
	"github.com/rosschiu/kiban/internal/httpx"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/errenv"
)

// Routes builds the org service's HTTP handler (stdlib net/http, Go 1.22+ pattern routing —
// same layout as registry and identity). Reads are open; mutations are guarded by
// AdminAuthorizer (fail-closed) and audited in-transaction.
func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /internal/org/units", svc.handleCreateUnit)
	mux.HandleFunc("GET /internal/org/units/{id}", svc.handleGetUnit)
	mux.HandleFunc("PUT /internal/org/units/{id}", svc.handleUpdateUnit)
	mux.HandleFunc("DELETE /internal/org/units/{id}", svc.handleDeleteUnit)
	mux.HandleFunc("GET /internal/org/units/{id}/subtree", svc.handleSubtree)

	// Internal company-facts reads authz's decision-order step 5 depends on. Open reads (no
	// AdminAuthorizer guard), same "internal, unauthenticated read" shape identity's own
	// GET /internal/identity/users/{kcSub}/state uses — these are internal-network-only facts,
	// not user-facing data.
	mux.HandleFunc("GET /internal/org/companies/{id}/state", svc.handleCompanyState)
	mux.HandleFunc("GET /internal/org/companies/{id}/members/by-kcsub/{kcSub}", svc.handleMemberByKcSub)

	// The company-switcher source — active-membership companies for a kcSub. Same "internal,
	// unauthenticated read, kcSub taken as a param" shape as the two company-facts reads above:
	// self-scoped by construction (kcSub is the caller's own identity — a query param at this
	// internal layer; the gateway injects the bearer's own kcSub and never lets a client name a
	// different one).
	mux.HandleFunc("GET /internal/org/me/companies", svc.handleMeCompanies)

	// The browser-reachable member directory (share-with/assign-to picker). New
	// handler, deliberately NOT a reuse of handleListMembers — REDUCED view (no kcSub/code/
	// lifecycle) and self-scoped-or-admin gated, where handleListMembers returns the FULL
	// admin-console shape. Gateway route: GET /api/org/companies/{companyId}/members.
	mux.HandleFunc("GET /internal/org/companies/{id}/members", svc.handleMemberDirectory)

	// The sample shell's minimal position-admin surface — list-with-holder (the shape
	// handleListPositions doesn't have) and create-from-path (companyId taken from the path only,
	// body company/org-unit IDs rejected — see handleAdminCreatePosition). Reachable ONLY via the
	// gateway's superadmin-gated `/api/org/admin/...` routes (internal/gateway/
	// admin_position_routes.go); same "internal read, gateway is the trust boundary" posture as
	// the company-facts reads above for the GET, defense-in-depth authorize() for the POST (same as
	// every other org mutation).
	mux.HandleFunc("GET /internal/org/companies/{id}/positions", svc.handleAdminPositionList)
	mux.HandleFunc("POST /internal/org/companies/{id}/positions", svc.handleAdminCreatePosition)

	// The group admin surface — same "internal read, gateway is the trust boundary"
	// posture as the position admin surface above; add/remove-member both call authorize() (the
	// single-writer invariant is enforced independently, in the STORE, and returns 409
	// GROUP_EXTERNALLY_MANAGED regardless of who calls — this authorize() gate is "may this
	// caller administer groups at all", a separate question).
	mux.HandleFunc("GET /internal/org/companies/{id}/groups", svc.handleAdminGroupList)
	mux.HandleFunc("POST /internal/org/companies/{id}/groups", svc.handleAdminCreateGroup)
	// A single-group-by-id read — a module's group-binding path (e.g. helpdesk) needs this the
	// same way a position binding needs handleGetPosition (company-mismatch check, title display
	// snapshot); same S2S-read posture as every other internal org fact read, not an admin
	// surface.
	mux.HandleFunc("GET /internal/org/groups/{id}", svc.handleGetGroup)
	mux.HandleFunc("GET /internal/org/groups/{id}/members", svc.handleListGroupMembers)
	mux.HandleFunc("POST /internal/org/groups/{id}/members", svc.handleAddGroupMember)
	mux.HandleFunc("DELETE /internal/org/groups/{id}/members/{memberId}", svc.handleRemoveGroupMember)

	mux.HandleFunc("POST /internal/org/members", svc.handleCreateMember)
	mux.HandleFunc("GET /internal/org/members", svc.handleListMembers)
	mux.HandleFunc("GET /internal/org/members/{id}", svc.handleGetMember)
	mux.HandleFunc("PUT /internal/org/members/{id}", svc.handleUpdateMember)
	mux.HandleFunc("POST /internal/org/members/{id}/link-user", svc.handleLinkUser)
	mux.HandleFunc("DELETE /internal/org/members/{id}/link-user", svc.handleUnlinkUser)

	mux.HandleFunc("POST /internal/org/positions", svc.handleCreatePosition)
	mux.HandleFunc("GET /internal/org/positions", svc.handleListPositions)
	mux.HandleFunc("GET /internal/org/positions/{id}", svc.handleGetPosition)
	mux.HandleFunc("PUT /internal/org/positions/{id}", svc.handleUpdatePosition)
	mux.HandleFunc("DELETE /internal/org/positions/{id}", svc.handleDeletePosition)
	mux.HandleFunc("GET /internal/org/positions/{id}/holder", svc.handleHolderOnDate)
	mux.HandleFunc("POST /internal/org/positions:create-and-assign", svc.handleCreateAndAssign)

	// assign-NOW (server-set valid_from = today; no caller-supplied dates) — Store.AssignNow
	// writes the assignment, its audit record, and the position-holder tuple grant.
	mux.HandleFunc("POST /internal/org/positions/{id}/assignments", svc.handleAssignNow)

	mux.HandleFunc("POST /internal/org/assignments/{id}/end", svc.handleEndAssignment)

	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", httpx.Ready(svc.store.Pool()))

	return mux
}

// ---- shared plumbing ------------------------------------------------------------------------

// authorize is the shared fail-closed gate for AdminAuthorizer-guarded mutations — same order as
// registry/identity: guard first, audit the denial (with authz's real reason for a confirmed
// denial → 403; AUTHORIZATION_UNAVAILABLE when no definite answer was reached → 503), only then
// touch the store.
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

// actorFor derives the audited actor for an org mutation. Handlers only populate
// AuthContext.RawBearer, so the actor is the bearer's `sub` claim. This is record-keeping ONLY
// (audit trail) — the actual authorization decision for every mutation this actor string is
// attached to has ALREADY been made by svc.authorize's call to authz's effective-access/can
// (which fully verifies the token); the rule never to use JWT claims as an authorization source
// is about decisions, not who gets named in the audit ledger for a decision already taken.
func actorFor(authCtx AuthContext) string {
	return httpx.ActorFor(authCtx.Subject, authCtx.RawBearer)
}

func parsePathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code:    errenv.CodeBadRequest,
			Message: "invalid " + name,
			Details: map[string]string{"field": name},
		})
		return uuid.UUID{}, false
	}
	return id, true
}

// writeStoreError maps the store's sentinel/ValidationError/ErrConflict shapes to the canonical
// HTTP status + error code.
func writeStoreError(w http.ResponseWriter, err error) {
	var vErr *ValidationError
	var refErr *ReferencedError
	switch {
	case errors.As(err, &vErr):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: vErr.Message, Details: map[string]string{"field": vErr.Field},
		})
	case errors.Is(err, ErrOrgUnitNotFound), errors.Is(err, ErrMemberNotFound),
		errors.Is(err, ErrPositionNotFound), errors.Is(err, ErrAssignmentNotFound),
		errors.Is(err, ErrGroupNotFound), errors.Is(err, ErrGroupMemberNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
	case errors.Is(err, ErrAssignmentAlreadyEnded):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{
			Code: errenv.CodeAssignmentAlreadyEnded, Message: "assignment already ended",
		})
	case errors.Is(err, ErrGroupExternallyManaged):
		// The single-writer invariant (409 GROUP_EXTERNALLY_MANAGED), enforced in the
		// store — this handler-level mapping never makes the decision, only reports it.
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{
			Code: errenv.CodeGroupExternallyManaged, Message: "group is externally managed — membership is read-only here",
		})
	case errors.Is(err, ErrOrgUnitHasChildren):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: "org unit has children", Details: map[string]string{"field": "id"},
		})
	case errors.Is(err, ErrOrgUnitHasMembers):
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: "org unit has members", Details: map[string]string{"field": "id"},
		})
	case isPositionBoundError(err):
		var boundErr *PositionBoundError
		errors.As(err, &boundErr)
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{
			Code:    errenv.CodeConflict,
			Message: "position is bound to " + strconv.Itoa(boundErr.Count) + " module grant(s)",
			Details: map[string]string{"count": strconv.Itoa(boundErr.Count)},
		})
	case errors.As(err, &refErr):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{
			Code: errenv.CodeConflict, Message: "still referenced by org." + refErr.Table, Details: map[string]string{"field": refErr.Table},
		})
	case errors.Is(err, ErrConflict):
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeConflict, Message: "conflict"})
	default:
		httpx.WriteInternalError(w, err)
	}
}

func isPositionBoundError(err error) bool {
	var boundErr *PositionBoundError
	return errors.As(err, &boundErr)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid request body"})
		return false
	}
	return true
}

// pageParams reads page/pageSize; an over-limit value (page > 10 000, pageSize > 100) is a 400
// VALIDATION_ERROR naming the field, so no OFFSET is ever computed from it. Missing, non-numeric
// or sub-minimum values fall through to clampPage's defaults, as before.
func pageParams(w http.ResponseWriter, r *http.Request) (page, pageSize int, ok bool) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ = strconv.Atoi(r.URL.Query().Get("pageSize"))
	field := ""
	switch {
	case page > maxPage:
		field = "page"
	case pageSize > maxPageSize:
		field = "pageSize"
	}
	if field != "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code: errenv.CodeValidationError, Message: field + " exceeds the maximum", Details: map[string]string{"field": field},
		})
		return 0, 0, false
	}
	return page, pageSize, true
}

// ---- org units --------------------------------------------------------------------------

type unitRequest struct {
	TypeKey  string  `json:"typeKey"`
	ParentID *string `json:"parentId"`
	Code     string  `json:"code"`
	Name     string  `json:"name"`
	IsActive *bool   `json:"isActive"`
}

func (svc *Service) handleCreateUnit(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.unit.create", "org_unit:new") {
		return
	}
	var req unitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	parentID, ok := parseOptionalUUID(w, req.ParentID, "parentId")
	if !ok {
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	unit, err := svc.store.CreateOrgUnit(r.Context(), actorFor(authCtx), req.TypeKey, parentID, req.Code, req.Name, isActive)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, unitView(unit))
}

func parseOptionalUUID(w http.ResponseWriter, s *string, field string) (*uuid.UUID, bool) {
	if s == nil || *s == "" {
		return nil, true
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid " + field, Details: map[string]string{"field": field}})
		return nil, false
	}
	return &id, true
}

func (svc *Service) handleGetUnit(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	unit, err := svc.store.GetOrgUnit(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, unitView(unit))
}

func (svc *Service) handleUpdateUnit(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.unit.update", "org_unit:"+id.String()) {
		return
	}
	var req unitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	parentID, ok := parseOptionalUUID(w, req.ParentID, "parentId")
	if !ok {
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	unit, err := svc.store.UpdateOrgUnit(r.Context(), actorFor(authCtx), id, parentID, req.Code, req.Name, isActive)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, unitView(unit))
}

func (svc *Service) handleDeleteUnit(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.unit.delete", "org_unit:"+id.String()) {
		return
	}
	if err := svc.store.DeleteOrgUnit(r.Context(), actorFor(authCtx), id); err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"id": id.String()})
}

func (svc *Service) handleSubtree(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	units, err := svc.store.Subtree(r.Context(), id)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(units))
	for _, u := range units {
		v := unitView(u)
		v["depth"] = u.Depth
		views = append(views, v)
	}
	errenv.WriteData(w, http.StatusOK, views)
}

func unitView(u OrgUnit) map[string]any {
	var parentID any
	if u.ParentID != nil {
		parentID = u.ParentID.String()
	}
	return map[string]any{
		"id":       u.ID.String(),
		"typeKey":  u.TypeKey,
		"parentId": parentID,
		"code":     u.Code,
		"name":     u.Name,
		"isActive": u.IsActive,
	}
}

// ---- company facts ------------------------------------------------------------------------

// handleCompanyState answers `GET /internal/org/companies/{id}/state` — decision.CompanySource
// (effective-access decision step 5). {"exists":false} covers both "no such
// org_unit" and "org_unit exists but isn't company-typed" — the caller never needs to
// distinguish those two, and the store never fabricates a company for the wrong type of unit.
func (svc *Service) handleCompanyState(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	exists, isActive, err := svc.store.CompanyState(r.Context(), id)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]any{"exists": exists, "isActive": isActive})
}

// handleMemberByKcSub answers `GET /internal/org/companies/{id}/members/by-kcsub/{kcSub}` —
// decision.MembershipSource (step 5). isMember=false (memberId omitted) covers "no member row
// links this kcSub in this company" — never a fabricated membership.
func (svc *Service) handleMemberByKcSub(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	kcSub := r.PathValue("kcSub")
	isMember, memberID, isActive, err := svc.store.MemberByCompanyAndKcSub(r.Context(), id, kcSub)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	resp := map[string]any{"isMember": isMember, "isActive": isActive}
	if isMember {
		resp["memberId"] = memberID.String()
	} else {
		resp["memberId"] = nil
	}
	errenv.WriteData(w, http.StatusOK, resp)
}

// handleMeCompanies answers `GET /internal/org/me/companies?kcSub=` — the company-switcher
// source: companies where kcSub has an active membership in an active company.
// kcSub is required (400 if missing/blank); an unknown kcSub or one with no active memberships
// answers an empty list, never an error — same "no fabricated result" posture as the company-facts reads.
func (svc *Service) handleMeCompanies(w http.ResponseWriter, r *http.Request) {
	kcSub := r.URL.Query().Get("kcSub")
	if kcSub == "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code: errenv.CodeBadRequest, Message: "kcSub query param is required", Details: map[string]string{"field": "kcSub"},
		})
		return
	}
	companies, err := svc.store.ListActiveCompaniesForKcSub(r.Context(), kcSub)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(companies))
	for _, c := range companies {
		views = append(views, map[string]any{
			"id": c.ID.String(), "code": c.Code, "name": c.Name, "isActive": c.IsActive,
		})
	}
	errenv.WriteData(w, http.StatusOK, views)
}

// requireMemberOrAdmin is the gate shared by handleMemberDirectory and handleListMembers: the
// caller must EITHER be an ACTIVE member of companyID (proven by kcSub, injected by the gateway
// from the validated bearer — internal/gateway/foundation_routes.go's newSubjectScopedProxy
// pattern — same "internal read, caller supplies kcSub" shape as the company-facts reads) OR the platform superadmin (proven by
// forwarding the caller's raw bearer to svc.authz, the same AdminAuthorizer every mutation route
// already uses). kcSub missing/blank is 400 (a caller that can't name itself can't be a member);
// anything else that isn't a confirmed member or a confirmed admin is 403 — fail-closed, never a
// guessed allow (an AdminAuthorizer error, e.g. AUTHORIZATION_UNAVAILABLE, is treated as "not
// admin", not as "unavailable", since a non-member's request must still resolve to a definite
// answer and membership itself is a plain fact query, not an admin decision).
func (svc *Service) requireMemberOrAdmin(w http.ResponseWriter, r *http.Request, companyID uuid.UUID) (kcSub string, ok bool) {
	kcSub = r.URL.Query().Get("kcSub")
	if kcSub == "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{
			Code: errenv.CodeBadRequest, Message: "kcSub query param is required", Details: map[string]string{"field": "kcSub"},
		})
		return "", false
	}

	isMember, _, isActive, err := svc.store.MemberByCompanyAndKcSub(r.Context(), companyID, kcSub)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return "", false
	}
	if isMember && isActive {
		return kcSub, true
	}

	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if adminOK, adminErr := svc.authz.Can(r.Context(), authCtx, "org.members.read"); adminErr == nil && adminOK {
		return kcSub, true
	}

	errenv.WriteError(w, http.StatusForbidden, errenv.APIError{
		Code: errenv.CodeForbidden, Message: "not an active member of this company",
	})
	return "", false
}

// handleMemberDirectory answers `GET /internal/org/companies/{id}/members?kcSub=&q=&page=&pageSize=`
// — the member picker: a REDUCED view (id/displayName/email/hasLinkedUser, least disclosure —
// no kcSub, no code, no lifecycle) over companyID's ACTIVE
// members, gated by requireMemberOrAdmin above. q is an optional case-insensitive substring
// filter over displayName/email (parameterized ILIKE, SQL-side).
func (svc *Service) handleMemberDirectory(w http.ResponseWriter, r *http.Request) {
	companyID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, ok := svc.requireMemberOrAdmin(w, r, companyID); !ok {
		return
	}

	q := r.URL.Query().Get("q")
	page, pageSize, ok := pageParams(w, r)
	if !ok {
		return
	}
	entries, total, err := svc.store.MemberDirectory(r.Context(), companyID, q, page, pageSize)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	page, pageSize = clampPage(page, pageSize)
	views := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		views = append(views, map[string]any{
			"id": e.ID.String(), "displayName": e.DisplayName, "email": e.Email, "hasLinkedUser": e.HasLinkedUser,
		})
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[map[string]any]{Items: views, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

// ---- members ------------------------------------------------------------------------------

type memberRequest struct {
	CompanyID   string `json:"companyId"`
	Code        string `json:"code"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	IsActive    *bool  `json:"isActive"`
}

func (svc *Service) handleCreateMember(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.member.create", "member:new") {
		return
	}
	var req memberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid companyId", Details: map[string]string{"field": "companyId"}})
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	member, err := svc.store.CreateMember(r.Context(), actorFor(authCtx), companyID, req.Code, req.DisplayName, req.Email, isActive)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, memberView(member))
}

func (svc *Service) handleGetMember(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	member, err := svc.store.GetMember(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, memberView(member))
}

// handleListMembers is the FULL admin-console member list (unlike handleMemberDirectory's
// REDUCED, gateway-facing view), gated with the same requireMemberOrAdmin check
// handleMemberDirectory uses.
func (svc *Service) handleListMembers(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(r.URL.Query().Get("companyId"))
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid companyId query param", Details: map[string]string{"field": "companyId"}})
		return
	}
	if _, ok := svc.requireMemberOrAdmin(w, r, companyID); !ok {
		return
	}
	page, pageSize, ok := pageParams(w, r)
	if !ok {
		return
	}
	members, total, err := svc.store.ListMembers(r.Context(), companyID, page, pageSize)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	page, pageSize = clampPage(page, pageSize)
	views := make([]map[string]any, 0, len(members))
	for _, m := range members {
		views = append(views, memberView(m))
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[map[string]any]{Items: views, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

func (svc *Service) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.member.update", "member:"+id.String()) {
		return
	}
	var req memberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	member, err := svc.store.UpdateMember(r.Context(), actorFor(authCtx), id, req.DisplayName, req.Email, isActive)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, memberView(member))
}

type linkUserRequest struct {
	KcSub string `json:"kcSub"`
}

func (svc *Service) handleLinkUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.member.link_user", "member:"+id.String()) {
		return
	}
	var req linkUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	member, err := svc.store.LinkUser(r.Context(), actorFor(authCtx), svc.identity, id, req.KcSub)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, memberView(member))
}

func (svc *Service) handleUnlinkUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.member.unlink_user", "member:"+id.String()) {
		return
	}
	member, err := svc.store.UnlinkUser(r.Context(), actorFor(authCtx), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, memberView(member))
}

func memberView(m Member) map[string]any {
	var userID any
	if m.UserID != nil {
		userID = m.UserID.String()
	}
	v := map[string]any{
		"id":          m.ID.String(),
		"companyId":   m.CompanyID.String(),
		"code":        m.Code,
		"displayName": m.DisplayName,
		"email":       m.Email,
		"userId":      userID,
		"isActive":    m.IsActive,
	}
	if m.UserID != nil {
		v["user"] = map[string]any{
			"kcSub":             m.UserKcSub,
			"email":             m.UserEmail,
			"preferredUsername": m.UserPreferredUsername,
			"lifecycle":         m.UserLifecycle,
		}
	}
	return v
}

// ---- positions ----------------------------------------------------------------------------

type positionRequest struct {
	CompanyID string `json:"companyId"`
	Code      string `json:"code"`
	Title     string `json:"title"`
	OrgUnitID string `json:"orgUnitId"`
}

func (svc *Service) handleCreatePosition(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.position.create", "position:new") {
		return
	}
	var req positionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	companyID, err1 := uuid.Parse(req.CompanyID)
	orgUnitID, err2 := uuid.Parse(req.OrgUnitID)
	if err1 != nil || err2 != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid companyId/orgUnitId"})
		return
	}
	position, err := svc.store.CreatePosition(r.Context(), actorFor(authCtx), companyID, req.Code, req.Title, orgUnitID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, positionView(position))
}

func (svc *Service) handleGetPosition(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	position, err := svc.store.GetPosition(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, positionView(position))
}

func (svc *Service) handleListPositions(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(r.URL.Query().Get("companyId"))
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid companyId query param", Details: map[string]string{"field": "companyId"}})
		return
	}
	page, pageSize, ok := pageParams(w, r)
	if !ok {
		return
	}
	positions, total, err := svc.store.ListPositions(r.Context(), companyID, page, pageSize)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	page, pageSize = clampPage(page, pageSize)
	views := make([]map[string]any, 0, len(positions))
	for _, p := range positions {
		views = append(views, positionView(p))
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[map[string]any]{Items: views, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

// ---- admin position surface ----------------------------------------------------------------

// handleAdminPositionList answers `GET /internal/org/companies/{id}/positions?page=&pageSize=` —
// the admin list: each row carries the position PLUS its current assignment
// (assignmentId/memberId/holderDisplayName, all null when unassigned) so the UI can render "who
// holds this seat" and END a tenure without a second round trip.
func (svc *Service) handleAdminPositionList(w http.ResponseWriter, r *http.Request) {
	companyID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	page, pageSize, ok := pageParams(w, r)
	if !ok {
		return
	}
	positions, total, err := svc.store.ListPositionsWithHolder(r.Context(), companyID, page, pageSize)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	page, pageSize = clampPage(page, pageSize)
	views := make([]map[string]any, 0, len(positions))
	for _, p := range positions {
		views = append(views, positionWithHolderView(p))
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[map[string]any]{Items: views, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

func positionWithHolderView(p PositionWithHolder) map[string]any {
	v := positionView(p.Position)
	var assignmentID, memberID, holderName any
	if p.AssignmentID != nil {
		assignmentID = p.AssignmentID.String()
	}
	if p.AssignmentMemberID != nil {
		memberID = p.AssignmentMemberID.String()
	}
	if p.HolderDisplayName != nil {
		holderName = *p.HolderDisplayName
	}
	v["assignmentId"] = assignmentID
	v["memberId"] = memberID
	v["holderDisplayName"] = holderName
	return v
}

// adminCreatePositionRequest is handleAdminCreatePosition's body shape — deliberately narrower
// than positionRequest: companyId comes from the PATH only, and orgUnitId isn't accepted at all
// (defaults to the company root). Both are still DECODED (as optional pointers) purely so a
// caller that supplies either gets an explicit 422 naming the field, never a silent ignore — a
// body companyId/orgUnitId is rejected, not trusted.
type adminCreatePositionRequest struct {
	Code      string  `json:"code"`
	Title     string  `json:"title"`
	CompanyID *string `json:"companyId"`
	OrgUnitID *string `json:"orgUnitId"`
}

// handleAdminCreatePosition answers `POST /internal/org/companies/{id}/positions` {code,title} —
// the admin create: companyId is taken from the path only (a body companyId/orgUnitId
// is rejected with 422, never trusted — the legacy handleCreatePosition's trust gap this surface
// deliberately does NOT inherit), org-unit defaults to the company's own root org_unit (id ==
// companyID; orgUnitUnderCompany treats a unit as under itself).
func (svc *Service) handleAdminCreatePosition(w http.ResponseWriter, r *http.Request) {
	companyID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.position.create", "position:new") {
		return
	}
	var req adminCreatePositionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.CompanyID != nil && *req.CompanyID != "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: "companyId is derived from the path and must not be set in the body",
			Details: map[string]string{"field": "companyId"},
		})
		return
	}
	if req.OrgUnitID != nil && *req.OrgUnitID != "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: "orgUnitId is not accepted on this route (defaults to the company root)",
			Details: map[string]string{"field": "orgUnitId"},
		})
		return
	}
	position, err := svc.store.CreatePosition(r.Context(), actorFor(authCtx), companyID, req.Code, req.Title, companyID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, positionView(position))
}

func (svc *Service) handleUpdatePosition(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.position.update", "position:"+id.String()) {
		return
	}
	var req positionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	orgUnitID, err := uuid.Parse(req.OrgUnitID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid orgUnitId", Details: map[string]string{"field": "orgUnitId"}})
		return
	}
	position, err := svc.store.UpdatePosition(r.Context(), actorFor(authCtx), id, req.Title, orgUnitID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, positionView(position))
}

func (svc *Service) handleDeletePosition(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.position.delete", "position:"+id.String()) {
		return
	}
	if err := svc.store.DeletePosition(r.Context(), actorFor(authCtx), id); err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"id": id.String()})
}

func (svc *Service) handleHolderOnDate(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	dateStr := r.URL.Query().Get("date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid date query param (want YYYY-MM-DD)", Details: map[string]string{"field": "date"}})
		return
	}
	assignment, err := svc.store.AssignmentOnDate(r.Context(), id, date)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, assignmentView(assignment))
}

func positionView(p Position) map[string]any {
	return map[string]any{
		"id": p.ID.String(), "companyId": p.CompanyID.String(), "code": p.Code, "title": p.Title, "orgUnitId": p.OrgUnitID.String(),
	}
}

func assignmentView(a Assignment) map[string]any {
	var validTo any
	if a.ValidTo != nil {
		validTo = a.ValidTo.Format("2006-01-02")
	}
	return map[string]any{
		"id": a.ID.String(), "positionId": a.PositionID.String(), "memberId": a.MemberID.String(),
		"validFrom": a.ValidFrom.Format("2006-01-02"), "validTo": validTo,
	}
}

// ---- combined create+assign / assignment end -----------------------------------------------

type createAndAssignRequest struct {
	CompanyID string  `json:"companyId"`
	Code      string  `json:"code"`
	Title     string  `json:"title"`
	OrgUnitID string  `json:"orgUnitId"`
	MemberID  string  `json:"memberId"`
	ValidFrom string  `json:"validFrom"`
	ValidTo   *string `json:"validTo"`
}

func (svc *Service) handleCreateAndAssign(w http.ResponseWriter, r *http.Request) {
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.position.create_and_assign", "position:new") {
		return
	}
	var req createAndAssignRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	companyID, err1 := uuid.Parse(req.CompanyID)
	orgUnitID, err2 := uuid.Parse(req.OrgUnitID)
	memberID, err3 := uuid.Parse(req.MemberID)
	if err1 != nil || err2 != nil || err3 != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid companyId/orgUnitId/memberId"})
		return
	}
	validFrom, err := time.Parse("2006-01-02", req.ValidFrom)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid validFrom (want YYYY-MM-DD)", Details: map[string]string{"field": "validFrom"}})
		return
	}
	var validTo *time.Time
	if req.ValidTo != nil && *req.ValidTo != "" {
		t, err := time.Parse("2006-01-02", *req.ValidTo)
		if err != nil {
			errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid validTo (want YYYY-MM-DD)", Details: map[string]string{"field": "validTo"}})
			return
		}
		validTo = &t
	}

	position, assignment, err := svc.store.CreateAndAssign(r.Context(), actorFor(authCtx), companyID, req.Code, req.Title, orgUnitID, memberID, validFrom, validTo)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, map[string]any{"position": positionView(position), "assignment": assignmentView(assignment)})
}

// handleEndAssignment is the end-NOW surface: no request body is consulted (the server sets
// valid_to = today — no caller-supplied dates). A client that sends a {"validTo": ...} body is
// simply ignored, never honored.
func (svc *Service) handleEndAssignment(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.assignment.end", "assignment:"+id.String()) {
		return
	}
	assignment, err := svc.store.EndAssignment(r.Context(), actorFor(authCtx), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, assignmentView(assignment))
}

// ---- assign-NOW -----------------------------------------------------------------------------

type assignNowRequest struct {
	MemberID string `json:"memberId"`
}

// handleAssignNow answers `POST /internal/org/positions/{id}/assignments` — assign-NOW: server
// sets valid_from = today, grants the position-holder tuple, and audits org.assignment.create,
// all in Store.AssignNow's own transaction.
func (svc *Service) handleAssignNow(w http.ResponseWriter, r *http.Request) {
	positionID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.assignment.create", "position:"+positionID.String()) {
		return
	}
	var req assignNowRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	memberID, err := uuid.Parse(req.MemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid memberId", Details: map[string]string{"field": "memberId"}})
		return
	}
	assignment, err := svc.store.AssignNow(r.Context(), actorFor(authCtx), positionID, memberID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, assignmentView(assignment))
}

// ---- admin group surface --------------------------------------------------------------------

// handleAdminGroupList answers `GET /internal/org/companies/{id}/groups?page=&pageSize=` — every
// row carries its member count AND its source/externalRef (so the UI can render an
// externally-sourced group read-only with a source badge — none exist yet, but the shape is
// already here).
func (svc *Service) handleAdminGroupList(w http.ResponseWriter, r *http.Request) {
	companyID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	page, pageSize, ok := pageParams(w, r)
	if !ok {
		return
	}
	groups, total, err := svc.store.ListGroupsWithMemberCount(r.Context(), companyID, page, pageSize)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	page, pageSize = clampPage(page, pageSize)
	views := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		views = append(views, groupWithMemberCountView(g))
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	errenv.WriteData(w, http.StatusOK, errenv.Page[map[string]any]{Items: views, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages})
}

// adminCreateGroupRequest mirrors adminCreatePositionRequest's shape:
// companyId comes from the PATH only; a body companyId is decoded (as an optional pointer)
// purely so a caller that supplies one gets an explicit 422, never a silent ignore.
type adminCreateGroupRequest struct {
	Code      string  `json:"code"`
	Name      string  `json:"name"`
	CompanyID *string `json:"companyId"`
}

func (svc *Service) handleAdminCreateGroup(w http.ResponseWriter, r *http.Request) {
	companyID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.group.create", "group:new") {
		return
	}
	var req adminCreateGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.CompanyID != nil && *req.CompanyID != "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{
			Code: errenv.CodeValidationError, Message: "companyId is derived from the path and must not be set in the body",
			Details: map[string]string{"field": "companyId"},
		})
		return
	}
	group, err := svc.store.CreateGroup(r.Context(), actorFor(authCtx), companyID, req.Code, req.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, groupView(group))
}

// handleGetGroup answers `GET /internal/org/groups/{id}` — a single group's own facts (companyId/
// code/name/source/isKibanManaged), the S2S read a module binding a group (e.g. helpdesk) needs
// for its own company-mismatch check and display-snapshot title, mirroring handleGetPosition's
// role for the position path.
func (svc *Service) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	group, err := svc.store.GetGroup(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, groupView(group))
}

func (svc *Service) handleListGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	members, err := svc.store.ListGroupMembers(r.Context(), groupID)
	if err != nil {
		httpx.WriteInternalError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(members))
	for _, m := range members {
		views = append(views, groupMemberView(m))
	}
	errenv.WriteData(w, http.StatusOK, views)
}

type groupMemberRequest struct {
	MemberID string `json:"memberId"`
}

// handleAddGroupMember answers `POST /internal/org/groups/{id}/members` {memberId} — the
// single-writer invariant's write path. A group whose source isn't "kiban" 409s
// (GROUP_EXTERNALLY_MANAGED), enforced by Store.AddGroupMember itself, not by this handler.
func (svc *Service) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.group.member_add", "group:"+groupID.String()) {
		return
	}
	var req groupMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	memberID, err := uuid.Parse(req.MemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid memberId", Details: map[string]string{"field": "memberId"}})
		return
	}
	gm, err := svc.store.AddGroupMember(r.Context(), actorFor(authCtx), groupID, memberID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusCreated, groupMemberView(gm))
}

// handleRemoveGroupMember answers `DELETE /internal/org/groups/{id}/members/{memberId}` — the
// single-writer invariant's revocation path, same refusal as the add path.
func (svc *Service) handleRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, ok := parsePathUUID(w, r, "id")
	if !ok {
		return
	}
	memberID, ok := parsePathUUID(w, r, "memberId")
	if !ok {
		return
	}
	authCtx := AuthContext{RawBearer: r.Header.Get("Authorization")}
	if !svc.authorize(w, r, authCtx, "org.group.member_remove", "group:"+groupID.String()) {
		return
	}
	if err := svc.store.RemoveGroupMember(r.Context(), actorFor(authCtx), groupID, memberID); err != nil {
		writeStoreError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"groupId": groupID.String(), "memberId": memberID.String()})
}

func groupView(g Group) map[string]any {
	var externalRef any
	if g.ExternalRef != nil {
		externalRef = *g.ExternalRef
	}
	return map[string]any{
		"id": g.ID.String(), "companyId": g.CompanyID.String(), "code": g.Code, "name": g.Name,
		"source": g.Source, "externalRef": externalRef, "isActive": g.IsActive,
		"isKibanManaged": g.IsKibanManaged(),
	}
}

func groupWithMemberCountView(g GroupWithMemberCount) map[string]any {
	v := groupView(g.Group)
	v["memberCount"] = g.MemberCount
	return v
}

func groupMemberView(m GroupMember) map[string]any {
	var email any
	if m.MemberEmail != nil {
		email = *m.MemberEmail
	}
	return map[string]any{
		"groupId": m.GroupID.String(), "memberId": m.MemberID.String(), "addedBy": m.AddedBy,
		"addedAt": m.AddedAt.Format(time.RFC3339), "memberDisplayName": m.MemberDisplayName, "memberEmail": email,
	}
}

// ---- health/ready --------------------------------------------------------------------------

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}
