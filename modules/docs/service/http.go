// SPDX-License-Identifier: Apache-2.0

// Package docs implements the DocShare module service: per-document sharing with fine-grained
// authorization (owner/editor/viewer via Zanzibar tuples; a document nobody shared stays
// unreadable even to the superadmin). Built solely against the platform's Go "SDK" packages
// (internal/errenv, internal/audit, internal/httpx, internal/obs, internal/config, modulekit) plus
// HTTP calls to org's company-facts API, authz's effective-access/grants API, and notification's
// targeted-events API — never by reaching into any foundation schema.
package docs

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/errenv"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/modulekit"
)

// Service wires the docs module's HTTP surface: bearer verification + per-operation authz
// decision — company-scoped feature checks (docs.create/docs.manage) for the two routes that
// need them, and the OBJECT-mode check (docs_document owner/editor/viewer) for every
// per-document route. This is the module's central authorization boundary: the read-side share
// index (store.go) is NEVER consulted for an allow/deny decision, only for listing.
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
	featureDocsManage = "docs.manage"
	featureDocsCreate = "docs.create"
)

func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	svc.mountRoutes(mux)
	return mux
}

func (svc *Service) mountRoutes(mux modulekit.MuxHandleFunc) {
	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", svc.handleReady)

	mux.HandleFunc("GET /api/docs/v1/companies/{companyId}/documents", svc.withAuth(featureDocsCreate, svc.handleListDocuments))
	mux.HandleFunc("POST /api/docs/v1/companies/{companyId}/documents", svc.withAuth(featureDocsCreate, svc.handleCreateDocument))

	mux.HandleFunc("GET /api/docs/v1/companies/{companyId}/documents/{docId}", svc.withObjectAuth("viewer", svc.handleGetDocument))
	mux.HandleFunc("PUT /api/docs/v1/companies/{companyId}/documents/{docId}", svc.withObjectAuth("editor", svc.handleUpdateDocument))
	mux.HandleFunc("DELETE /api/docs/v1/companies/{companyId}/documents/{docId}", svc.withObjectAuth("owner", svc.handleDeleteDocument))

	mux.HandleFunc("GET /api/docs/v1/companies/{companyId}/documents/{docId}/shares", svc.withObjectAuth("viewer", svc.handleListShares))
	mux.HandleFunc("POST /api/docs/v1/companies/{companyId}/documents/{docId}/shares", svc.withObjectAuth("owner", svc.handleCreateShare))
	mux.HandleFunc("DELETE /api/docs/v1/companies/{companyId}/documents/{docId}/shares/{memberId}", svc.withObjectAuth("owner", svc.handleRevokeShare))

	mux.HandleFunc("GET /api/docs/v1/companies/{companyId}/documents/{docId}/audit", svc.withObjectAuth("viewer", svc.handleGetDocumentAudit))
	mux.HandleFunc("GET /api/docs/v1/companies/{companyId}/audit", svc.withAuth(featureDocsManage, svc.handleGetModuleAudit))
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
	DocID     uuid.UUID // zero value for company-scoped-only routes
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

// withAuth gates a company-scoped, FEATURE-only route (docs.create/docs.manage) — same shape as
// every other module's own withAuth (notification's http.go is the reference).
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
		next(w, r, requestContext{Subject: subject, RawBearer: rawBearer, CompanyID: companyID})
	}
}

// withObjectAuth gates a per-document route on docs's OWN object type (docs_document) — the
// object-mode check, this module's primary authorization decision. relation is
// "viewer" (read: GET document/shares/audit — resolves via the union to editor/owner too),
// "editor" (PUT document), or "owner" (DELETE document, share grant/revoke). A 404
// (ErrDocumentNotFound) is deliberately indistinguishable from a 403 in spirit but returned as
// its own code by the handler after the object check passes — the object check itself denies
// BEFORE the handler ever queries the document row, so an unauthorized caller can never even
// learn whether the id exists (this is the excludability property working as designed: engine
// truth, never the local row, decides "no").
func (svc *Service) withObjectAuth(relation string, next func(http.ResponseWriter, *http.Request, requestContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, rawBearer, ok := svc.verifyBearer(w, r)
		if !ok {
			return
		}
		companyID, ok := modulekit.ParsePathUUID(w, r, "companyId")
		if !ok {
			return
		}
		docID, ok := modulekit.ParsePathUUID(w, r, "docId")
		if !ok {
			return
		}
		allowed, reason, err := svc.Authz.CanObject(r.Context(), rawBearer, companyID.String(), docID.String(), relation)
		if err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not verify authorization"})
			return
		}
		if !allowed {
			errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "not authorized: " + reason})
			return
		}
		next(w, r, requestContext{Subject: subject, RawBearer: rawBearer, CompanyID: companyID, DocID: docID})
	}
}

// bearerFromHeader is referenced by this package's tests.
var bearerFromHeader = modulekit.BearerFromHeader

func writeStoreError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeValidationError, Message: verr.Message, Details: map[string]string{"field": verr.Field}})
	case errors.Is(err, ErrDocumentNotFound), errors.Is(err, ErrShareNotFound):
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "not found"})
	case errors.Is(err, ErrIdempotencyConflict):
		// Same Idempotency-Key, different payload.
		errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
	default:
		errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
	}
}

// ---- documents -------------------------------------------------------------------------------

type documentWire struct {
	ID         string `json:"id"`
	CompanyID  string `json:"companyId"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	OwnerKcSub string `json:"ownerKcSub"`
	MyRelation string `json:"myRelation,omitempty"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

const rfc3339 = "2006-01-02T15:04:05.999999999Z07:00"

func toDocumentWire(d Document) documentWire {
	return documentWire{
		ID: d.ID.String(), CompanyID: d.CompanyID.String(), Title: d.Title, Body: d.Body,
		OwnerKcSub: d.OwnerKcSub, CreatedAt: d.CreatedAt.Format(rfc3339), UpdatedAt: d.UpdatedAt.Format(rfc3339),
	}
}

// myRelation determines the BEST relation label to report for the wire response (owner > editor
// > viewer) — an extra authz round trip when the caller isn't the owner, cheap and honest rather
// than guessed (never derived from the local share index alone).
func (svc *Service) myRelation(r *http.Request, rc requestContext, d Document) string {
	if d.OwnerKcSub == rc.Subject {
		return "owner"
	}
	if allowed, _, err := svc.Authz.CanObject(r.Context(), rc.RawBearer, rc.CompanyID.String(), d.ID.String(), "editor"); err == nil && allowed {
		return "editor"
	}
	return "viewer" // the withObjectAuth("viewer", ...) gate already confirmed at least this much
}

type createDocumentRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// handleCreateDocument: docs.create is membership-gated only (no relation leg). Grants
// docs_document:<id>#owner @ user:<creator> (plus the company_module pointer tuple) through
// authz BEFORE the row is ever persisted, so a document row never exists without its owner
// tuple (and the company_module pointer tuple) already in place.
func (svc *Service) handleCreateDocument(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req createDocumentRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}
	if idempotencyKey != "" {
		// Check for a replay/conflict BEFORE granting the owner tuple below,
		// so a replayed create-document request never issues a second (orphaned) grant.
		if existing, existingHash, ok, err := svc.Store.FindDocumentByIdempotencyKey(r.Context(), rc.CompanyID, rc.Subject, idempotencyKey); err != nil {
			errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
			return
		} else if ok {
			if existingHash != documentIdempotencyPayloadHash(rc.CompanyID, rc.Subject, req.Title, req.Body) {
				errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
				return
			}
			wire := toDocumentWire(existing)
			wire.MyRelation = "owner"
			errenv.WriteData(w, http.StatusOK, wire)
			return
		}
	}
	docID := uuid.New()
	if err := svc.Authz.GrantDocumentOwner(r.Context(), rc.RawBearer, rc.CompanyID.String(), docID.String(), rc.Subject, docID.String()); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant owner relation"})
		return
	}
	d, err := svc.Store.CreateDocument(r.Context(), docID, rc.Subject, rc.CompanyID, req.Title, req.Body, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := toDocumentWire(d)
	wire.MyRelation = "owner"
	errenv.WriteData(w, http.StatusCreated, wire)
}

// handleListDocuments: owned (plain DB read — the owner tuple was granted atomically at create
// time) + shared-with-me (the share index's CANDIDATE ids, each VERIFIED via batch object-check
// before return — belt and braces, the engine is the source of truth).
func (svc *Service) handleListDocuments(w http.ResponseWriter, r *http.Request, rc requestContext) {
	owned, err := svc.Store.ListOwnedDocuments(r.Context(), rc.CompanyID, rc.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var sharedWithMe []Document
	memberID, isMember, _, err := svc.Org.MemberByKcSub(r.Context(), rc.CompanyID.String(), rc.Subject)
	if err == nil && isMember && memberID != "" {
		if mid, parseErr := uuid.Parse(memberID); parseErr == nil {
			candidateIDs, err := svc.Store.SharedDocumentIDsForMember(r.Context(), rc.CompanyID, mid)
			if err == nil && len(candidateIDs) > 0 {
				idStrs := make([]string, len(candidateIDs))
				for i, id := range candidateIDs {
					idStrs[i] = id.String()
				}
				verified, err := svc.Authz.BatchCanObject(r.Context(), rc.RawBearer, rc.CompanyID.String(), idStrs, "viewer")
				if err == nil {
					var verifiedIDs []uuid.UUID
					for _, id := range candidateIDs {
						if verified[id.String()] {
							verifiedIDs = append(verifiedIDs, id)
						}
					}
					sharedWithMe, _ = svc.Store.GetDocumentsByIDs(r.Context(), rc.CompanyID, verifiedIDs)
				}
			}
		}
	}

	ownedWire := make([]documentWire, len(owned))
	for i, d := range owned {
		w := toDocumentWire(d)
		w.MyRelation = "owner"
		ownedWire[i] = w
	}
	sharedWire := make([]documentWire, len(sharedWithMe))
	for i, d := range sharedWithMe {
		sharedWire[i] = toDocumentWire(d)
	}
	errenv.WriteData(w, http.StatusOK, map[string]any{"owned": ownedWire, "sharedWithMe": sharedWire})
}

func (svc *Service) handleGetDocument(w http.ResponseWriter, r *http.Request, rc requestContext) {
	d, err := svc.Store.GetDocument(r.Context(), rc.CompanyID, rc.DocID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := toDocumentWire(d)
	wire.MyRelation = svc.myRelation(r, rc, d)
	errenv.WriteData(w, http.StatusOK, wire)
}

type updateDocumentRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (svc *Service) handleUpdateDocument(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req updateDocumentRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	d, err := svc.Store.UpdateDocument(r.Context(), rc.Subject, rc.CompanyID, rc.DocID, req.Title, req.Body)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := toDocumentWire(d)
	wire.MyRelation = svc.myRelation(r, rc, d)
	errenv.WriteData(w, http.StatusOK, wire)
}

func (svc *Service) handleDeleteDocument(w http.ResponseWriter, r *http.Request, rc requestContext) {
	if err := svc.Store.DeleteDocument(r.Context(), rc.Subject, rc.CompanyID, rc.DocID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- shares ------------------------------------------------------------------------------------

type shareWire struct {
	ID         string `json:"id"`
	DocumentID string `json:"documentId"`
	MemberID   string `json:"memberId"`
	Relation   string `json:"relation"`
	GrantedBy  string `json:"grantedBy"`
	CreatedAt  string `json:"createdAt"`
}

func toShareWire(sh Share) shareWire {
	return shareWire{
		ID: sh.ID.String(), DocumentID: sh.DocumentID.String(), MemberID: sh.MemberID.String(),
		Relation: sh.Relation, GrantedBy: sh.GrantedBy, CreatedAt: sh.CreatedAt.Format(rfc3339),
	}
}

func (svc *Service) handleListShares(w http.ResponseWriter, r *http.Request, rc requestContext) {
	shares, err := svc.Store.ListShares(r.Context(), rc.DocID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	wire := make([]shareWire, len(shares))
	for i, sh := range shares {
		wire[i] = toShareWire(sh)
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

type createShareRequest struct {
	MemberID string `json:"memberId"`
	Relation string `json:"relation"`
}

// handleCreateShare grants a member viewer/editor access, records the read-side index row, and
// fires a targeted notification event ("<name> shared '<title>' with you") — non-fatal if
// notification is unreachable (sharing must not depend on notification availability).
func (svc *Service) handleCreateShare(w http.ResponseWriter, r *http.Request, rc requestContext) {
	var req createShareRequest
	if !modulekit.DecodeJSON(w, r, &req) {
		return
	}
	if req.Relation != "viewer" && req.Relation != "editor" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: `relation must be "viewer" or "editor"`, Details: map[string]string{"field": "relation"}})
		return
	}
	memberID, err := uuid.Parse(req.MemberID)
	if err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "memberId must be a valid UUID", Details: map[string]string{"field": "memberId"}})
		return
	}

	member, err := svc.Org.GetMember(r.Context(), memberID.String())
	if err != nil || member.KcSub == "" {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: "memberId has no linked user to share with", Details: map[string]string{"field": "memberId"}})
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if len(idempotencyKey) > 200 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "Idempotency-Key must be <= 200 characters"})
		return
	}
	if idempotencyKey != "" {
		// Check for a replay/conflict BEFORE the grant/revoke dance below, so
		// a replayed create-share request never issues a second (orphaned) grant/revoke pair.
		if existing, existingHash, ok, err := svc.Store.FindShareByIdempotencyKey(r.Context(), rc.DocID, idempotencyKey); err != nil {
			errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: "internal error"})
			return
		} else if ok {
			if existingHash != shareIdempotencyPayloadHash(rc.DocID, memberID, req.Relation) {
				errenv.WriteError(w, http.StatusConflict, errenv.APIError{Code: errenv.CodeIdempotencyConflict, Message: "Idempotency-Key was already used with a different request payload"})
				return
			}
			errenv.WriteData(w, http.StatusOK, toShareWire(existing))
			return
		}
	}

	correlationID := rc.DocID.String() + ":" + memberID.String()

	// Upgrade/downgrade: if a share already exists for this member with a DIFFERENT relation,
	// revoke the OLD tuple before granting the new one — otherwise both tuples would coexist
	// (e.g. a viewer->editor upgrade would silently leave the original viewer tuple live too,
	// so a later revoke-to-none would still leave the member with residual read access via the
	// stale viewer tuple). GetShare returning ErrShareNotFound (first-ever share) is not an
	// error here.
	if existing, err := svc.Store.GetShare(r.Context(), rc.DocID, memberID); err == nil && existing.Relation != req.Relation {
		if err := svc.Authz.RevokeShare(r.Context(), rc.RawBearer, rc.CompanyID.String(), rc.DocID.String(), existing.Relation, member.KcSub, correlationID+":upgrade-revoke-old"); err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not revoke previous relation before upgrade"})
			return
		}
	} else if err != nil && !errors.Is(err, ErrShareNotFound) {
		writeStoreError(w, err)
		return
	}

	if err := svc.Authz.GrantShare(r.Context(), rc.RawBearer, rc.CompanyID.String(), rc.DocID.String(), req.Relation, member.KcSub, correlationID); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not grant relation"})
		return
	}
	sh, err := svc.Store.RecordShare(r.Context(), rc.Subject, rc.CompanyID, rc.DocID, memberID, req.Relation, rc.Subject, idempotencyKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	if doc, docErr := svc.Store.GetDocument(r.Context(), rc.CompanyID, rc.DocID); docErr == nil {
		msg := "A document, '" + doc.Title + "', was shared with you as " + req.Relation + "."
		_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, "Document shared: "+doc.Title, msg)
	}

	errenv.WriteData(w, http.StatusCreated, toShareWire(sh))
}

// handleRevokeShare revokes a member's access (owner-only — the route gate already required the
// "owner" relation; here we additionally forbid an owner revoking THEIR OWN access). The tuple
// is removed through authz's op:"revoke".
func (svc *Service) handleRevokeShare(w http.ResponseWriter, r *http.Request, rc requestContext) {
	memberID, ok := modulekit.ParsePathUUID(w, r, "memberId")
	if !ok {
		return
	}

	member, err := svc.Org.GetMember(r.Context(), memberID.String())
	if err != nil {
		errenv.WriteError(w, http.StatusNotFound, errenv.APIError{Code: errenv.CodeNotFound, Message: "member not found"})
		return
	}
	if member.KcSub != "" && member.KcSub == rc.Subject {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "the owner cannot revoke their own access"})
		return
	}

	sh, err := svc.Store.GetShare(r.Context(), rc.DocID, memberID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	correlationID := rc.DocID.String() + ":" + memberID.String() + ":revoke"
	if member.KcSub != "" {
		if err := svc.Authz.RevokeShare(r.Context(), rc.RawBearer, rc.CompanyID.String(), rc.DocID.String(), sh.Relation, member.KcSub, correlationID); err != nil {
			errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "could not revoke relation"})
			return
		}
	}
	if err := svc.Store.RemoveShare(r.Context(), rc.Subject, rc.CompanyID, rc.DocID, memberID); err != nil {
		writeStoreError(w, err)
		return
	}

	if doc, docErr := svc.Store.GetDocument(r.Context(), rc.CompanyID, rc.DocID); docErr == nil && member.KcSub != "" {
		msg := "Your access to '" + doc.Title + "' was revoked."
		_ = svc.Notification.SendEvent(r.Context(), rc.RawBearer, rc.CompanyID.String(), member.KcSub, "Document access revoked: "+doc.Title, msg)
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---- audit --------------------------------------------------------------------------------------

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

func (svc *Service) handleGetDocumentAudit(w http.ResponseWriter, r *http.Request, rc requestContext) {
	events, err := svc.Store.DocumentAudit(r.Context(), rc.DocID)
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

// handleGetModuleAudit is the docs.manage-gated module-wide admin view. The admin
// sees events, never document content: audit.docs__events is never written with body
// text, only titles/ids/relations, so this is structurally true, not just a UI convention).
func (svc *Service) handleGetModuleAudit(w http.ResponseWriter, r *http.Request, rc requestContext) {
	page, pageSize := modulekit.PageParams(r)
	events, total, err := svc.Store.ModuleAudit(r.Context(), rc.CompanyID, page, pageSize)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	modulekit.WritePage(w, events, total, page, pageSize, toAuditEventWire)
}
