// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/engine"
	"github.com/rosschiu/kiban/internal/authz/fragment"
	"github.com/rosschiu/kiban/internal/authz/store"
	"github.com/rosschiu/kiban/internal/errenv"
)

// Routes builds authz's HTTP handler. Every effective-access/grants endpoint requires a
// validated bearer (never an actor from a request body); `check` is diagnostics-only, wired
// only when Service.DebugCheck is true. The `summary` endpoint is the one deliberate exception
// to the bearer rule: it takes kcSub as a query param, the same "internal, unauthenticated
// read, caller supplies the identity" shape org's own internal facts endpoints use — the
// gateway is the bearer-validating boundary for it, injecting the caller's own kcSub, never
// trusting a client-supplied one.
func (svc *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /internal/authz/effective-access/can", svc.handleCan)
	mux.HandleFunc("POST /internal/authz/effective-access/batch-can", svc.handleBatchCan)
	mux.HandleFunc("GET /internal/authz/effective-access/summary", svc.handleSummary)
	mux.HandleFunc("POST /internal/authz/grants", svc.handleGrants)
	mux.HandleFunc("POST /internal/authz/platform-roles", svc.handleGrantPlatformRole)
	mux.HandleFunc("DELETE /internal/authz/platform-roles/{role}/{subjectId}", svc.handleRevokePlatformRole)

	if svc.DebugCheck {
		mux.HandleFunc("POST /internal/authz/check", svc.handleDebugCheck)
	}

	mux.HandleFunc("GET /health", svc.handleHealth)
	mux.HandleFunc("GET /ready", svc.handleReady)

	// /metrics (this service's Prometheus exposition) is not here: cmd/authz/main.go mounts it
	// OUTSIDE this Routes() mux, on its own top-level mux alongside metrics.Registry.Middleware(),
	// so a scrape never depends on svc.Metrics being reachable from in here.

	return mux
}

// bearerSubject extracts and validates the Authorization header, returning the kcSub. Any
// failure writes 401 AUTH_TOKEN_MISSING/INVALID and returns ok=false — callers must stop.
func (svc *Service) bearerSubject(w http.ResponseWriter, r *http.Request) (string, bool) {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{Code: errenv.CodeAuthTokenMissing, Message: "missing bearer token"})
		return "", false
	}
	token := strings.TrimPrefix(authz, prefix)
	sub, err := svc.Verifier.Verify(r.Context(), token)
	if err != nil {
		errenv.WriteError(w, http.StatusUnauthorized, errenv.APIError{Code: errenv.CodeAuthTokenInvalid, Message: "invalid bearer token"})
		return "", false
	}
	return sub, true
}

// objectRefWire / requestWire are the JSON wire shapes for effective-access requests. Note:
// there is deliberately NO "subjectId"/"actor" field here — the actor is always the bearer
// (Forbidden). A body that includes one is ignored, never honored (400 is reserved for a body
// that explicitly tries to name a DIFFERENT actor via the one field we do parse for it, below).
type objectRefWire struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type canRequestWire struct {
	ActorOverride         string        `json:"actorId,omitempty"` // if present and != bearer, 400 (Forbidden)
	FeatureKey            string        `json:"featureKey"`
	ModuleKey             string        `json:"moduleKey"`
	Scope                 string        `json:"scope"` // "global" | "company"
	CompanyID             string        `json:"companyId"`
	RequiredPlatformRole  string        `json:"requiredPlatformRole"`
	AllowPlatformOperator bool          `json:"allowPlatformOperatorCompanyScope"`
	RequiredCompanyRole   string        `json:"requiredCompanyRole"`
	Object                objectRefWire `json:"object"`
	Relation              string        `json:"relation"`
	RequiresEligibility   bool          `json:"requiresEligibility"`
	CorrelationID         string        `json:"correlationId"`
}

func (w canRequestWire) toDecisionRequest(subjectID string) decision.Request {
	scope := decision.ScopeCompany
	if w.Scope == "global" {
		scope = decision.ScopeGlobal
	}
	return decision.Request{
		SubjectID: subjectID, FeatureKey: w.FeatureKey, ModuleKey: w.ModuleKey, Scope: scope,
		CompanyID: w.CompanyID, RequiredPlatformRole: w.RequiredPlatformRole,
		AllowPlatformOperatorCompanyScope: w.AllowPlatformOperator, RequiredCompanyRole: w.RequiredCompanyRole,
		Object:              decision.ObjectRef{Type: w.Object.Type, ID: w.Object.ID},
		Relation:            w.Relation,
		RequiresEligibility: w.RequiresEligibility,
		CorrelationID:       w.CorrelationID,
	}
}

type decisionWire struct {
	Allowed  bool                `json:"allowed"`
	Reason   string              `json:"reason"`
	Evidence []decision.Evidence `json:"evidence"`
}

func toDecisionWire(d decision.Decision) decisionWire {
	return decisionWire{Allowed: d.Allowed, Reason: string(d.Reason), Evidence: d.Evidence}
}

// writeDecision maps a Decision to the wire response: DEPENDENCY_UNAVAILABLE ⇒ 503 (the
// enforcement-boundary mapping the effective-access rules require); every other
// outcome (allow or a named denial) ⇒ 200 with allowed:true/false.
func writeDecision(w http.ResponseWriter, d decision.Decision) {
	if d.Reason == decision.ReasonDependencyUnavailable {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{
			Code:    errenv.CodeAuthorizationUnavailable,
			Message: "authorization is unavailable",
			Details: map[string]any{"dependency": d.Dependency, "step": d.Step, "evidence": d.Evidence},
		})
		return
	}
	errenv.WriteData(w, http.StatusOK, toDecisionWire(d))
}

func (svc *Service) buildDecider(ctx context.Context) (*decision.Decider, error) {
	decider, _, err := svc.buildDeciderAndChecker(ctx)
	return decider, err
}

// buildDeciderAndChecker is buildDecider's superset: it also returns the fragment-aware
// EngineChecker it built the Decider's Engine dep from, for callers (the summary
// composition, summary.go) that need a raw relation check outside the ordered 8-step decision — e.g.
// "does this subject hold the company#admin relation" for roleBindings, independent of company-
// active/membership/module-state gating.
func (svc *Service) buildDeciderAndChecker(ctx context.Context) (*decision.Decider, decision.EngineChecker, error) {
	en, loaded, err := svc.effectiveEngine(ctx)
	if err != nil {
		return nil, nil, err
	}
	checker := fragmentEngineChecker{en: en, loaded: loaded}
	deps := decision.Deps{
		Subject: svc.subjectSource(), Keycloak: svc.keycloakSource(),
		PlatformRole: enginePlatformRoleSource{checker: checker},
		Company:      svc.companySource(),
		Membership:   svc.membershipSource(),
		CompanyRole:  engineCompanyRoleSource{checker: checker},
		ModuleState:  svc.moduleStateSource(),
		Engine:       checker,
		Model:        checker,
	}
	return decision.NewDecider(deps), checker, nil
}

// fragmentEngineChecker adapts fragment.Check (disabled-module aware) to decision.EngineChecker,
// and the loaded effective model to decision.RelationDefiner (the company-binding rule).
type fragmentEngineChecker struct {
	en     *engine.Engine
	loaded fragment.Loaded
}

func (c fragmentEngineChecker) Check(ctx context.Context, objType, objID, rel, subjType, subjID string) (bool, error) {
	return fragment.Check(ctx, c.en, c.loaded, objType, objID, rel, subjType, subjID)
}

// Defines reports whether the EFFECTIVE model (base + enabled fragments) defines rel on objType.
// A disabled module's type is absent from the effective model and therefore unbindable — a
// clean deny, consistent with fragment.Check's own inert-false posture.
func (c fragmentEngineChecker) Defines(objType, rel string) bool {
	_, ok := c.loaded.Model[objType][rel]
	return ok
}

// validateCanRequest is the shared body validation for /can and /batch-can: the actor is the
// bearer, business eligibility is not wired, and a global-scope check must name the platform
// role it requires (an empty role can never be held, so a request
// without one is malformed, not a denial). Writes the 400 and returns false on failure.
func validateCanRequest(w http.ResponseWriter, sub string, req canRequestWire) bool {
	if req.ActorOverride != "" && req.ActorOverride != sub {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "actorId must match the bearer subject, or be omitted"})
		return false
	}
	if req.RequiresEligibility {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeValidationError, Message: "requiresEligibility is not supported by this deployment", Details: map[string]any{"field": "requiresEligibility"}})
		return false
	}
	if req.Scope == "global" && req.RequiredPlatformRole == "" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeValidationError, Message: "requiredPlatformRole is required for global scope", Details: map[string]any{"field": "requiredPlatformRole"}})
		return false
	}
	return true
}

func (svc *Service) handleCan(w http.ResponseWriter, r *http.Request) {
	sub, ok := svc.bearerSubject(w, r)
	if !ok {
		return
	}
	var req canRequestWire
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return
	}
	if !validateCanRequest(w, sub, req) {
		return
	}
	decider, err := svc.buildDecider(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	d := svc.evaluate(r.Context(), decider, req.toDecisionRequest(sub))
	if !d.Allowed {
		svc.auditDenial(r.Context(), sub, req.FeatureKey, d)
	}
	writeDecision(w, d)
}

type batchItemWire struct {
	Object   objectRefWire `json:"object"`
	Relation string        `json:"relation"`
}

type batchCanRequestWire struct {
	canRequestWire
	Items []batchItemWire `json:"items"`
}

// maxBatchItems caps one /batch-can request: every item is an engine
// walk, and the denial audit row lists the denied items (maxAuditedDenials of them).
const (
	maxBatchItems      = 100
	maxAuditedDenials  = 50
	actionAccessDenied = "authz.effective_access.denied"
)

func (svc *Service) handleBatchCan(w http.ResponseWriter, r *http.Request) {
	sub, ok := svc.bearerSubject(w, r)
	if !ok {
		return
	}
	var req batchCanRequestWire
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return
	}
	if !validateCanRequest(w, sub, req.canRequestWire) {
		return
	}
	if len(req.Items) > maxBatchItems {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeValidationError, Message: fmt.Sprintf("items must not exceed %d entries", maxBatchItems), Details: map[string]any{"field": "items", "max": maxBatchItems}})
		return
	}
	decider, err := svc.buildDecider(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	items := make([]decision.BatchItem, len(req.Items))
	for i, it := range req.Items {
		items[i] = decision.BatchItem{Object: decision.ObjectRef{Type: it.Object.Type, ID: it.Object.ID}, Relation: it.Relation}
	}
	base := req.toDecisionRequest(sub)
	results := svc.evaluateBatch(r.Context(), decider, base, items)

	wire := make([]map[string]any, len(results))
	var denied []map[string]any
	for i, res := range results {
		if !res.Decision.Allowed && len(denied) < maxAuditedDenials {
			denied = append(denied, map[string]any{"object": res.Item.Object, "relation": res.Item.Relation, "reason": string(res.Decision.Reason)})
		}
		wire[i] = map[string]any{
			"object":   res.Item.Object,
			"relation": res.Item.Relation,
			"decision": toDecisionWire(res.Decision),
		}
	}
	if len(denied) > 0 {
		deniedCount := 0
		for _, res := range results {
			if !res.Decision.Allowed {
				deniedCount++
			}
		}
		svc.auditDenialPayload(r.Context(), sub, req.FeatureKey, map[string]any{
			"featureKey": req.FeatureKey, "deniedCount": deniedCount, "denied": denied, "truncated": deniedCount > len(denied),
		})
	}
	errenv.WriteData(w, http.StatusOK, wire)
}

func (svc *Service) auditDenial(ctx context.Context, actor, featureKey string, d decision.Decision) {
	svc.auditDenialPayload(ctx, actor, featureKey, map[string]any{"reason": string(d.Reason), "featureKey": featureKey})
}

// auditDenialPayload writes ONE denial audit row in its own transaction — one per request, a
// batch's denied items ride in the payload.
func (svc *Service) auditDenialPayload(ctx context.Context, actor, featureKey string, payload map[string]any) {
	tx, err := svc.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := svc.Audit.Record(ctx, tx, audit.Event{Actor: actor, Action: actionAccessDenied, Subject: featureKey, Payload: payload}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// --- grants (the transactional store, exposed over HTTP with ITS OWN transaction) ---

type tupleWire struct {
	ObjectType      string `json:"objectType"`
	ObjectID        string `json:"objectId"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subjectType"`
	SubjectID       string `json:"subjectId"`
	SubjectRelation string `json:"subjectRelation"`
}

type grantsRequestWire struct {
	Op            string      `json:"op"` // "grant" | "revoke"
	CompanyID     string      `json:"companyId"`
	Tuples        []tupleWire `json:"tuples"`
	CorrelationID string      `json:"correlationId"`
}

func writeValidationFailed(w http.ResponseWriter, msg string) {
	errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationFailed, Message: msg})
}

// handleGrants writes or removes tuples, bound to the request's company and gated on the
// bearer: every tuple's object must belong to ONE enabled module M —
// a type M's fragment declares, or `company_module:<companyId>/<M>` — never a base type; a
// module object must carry its company_module anchor pointing at `<companyId>/<M>` (an anchor
// tuple in the same grant request counts, which is how create writes owner + anchor at once);
// the bearer must pass decision steps 1–6 for (M, companyId) (platform operators take the
// named exception); and a company_module tuple additionally needs the bearer to hold
// `company_module:<companyId>/<M>#admin`. Every refusal is fail-closed before any write.
func (svc *Service) handleGrants(w http.ResponseWriter, r *http.Request) {
	sub, ok := svc.bearerSubject(w, r)
	if !ok {
		return
	}
	var req grantsRequestWire
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return
	}
	if req.Op != "grant" && req.Op != "revoke" {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: `op must be "grant" or "revoke"`})
		return
	}
	if len(req.Tuples) == 0 {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "tuples must not be empty"})
		return
	}
	if _, err := uuid.Parse(req.CompanyID); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "companyId is required and must be a UUID", Details: map[string]any{"field": "companyId"}})
		return
	}
	tuples := make([]store.Tuple, len(req.Tuples))
	for i, t := range req.Tuples {
		tuples[i] = store.Tuple{ObjectType: t.ObjectType, ObjectID: t.ObjectID, Relation: t.Relation, SubjectType: t.SubjectType, SubjectID: t.SubjectID, SubjectRelation: t.SubjectRelation}
	}

	decider, checker, err := svc.buildDeciderAndChecker(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	loaded := checker.(fragmentEngineChecker).loaded

	// Rule 1 — every object resolves to one module M; one M per request.
	moduleKey := ""
	for _, t := range tuples {
		var m string
		if t.ObjectType == "company_module" {
			m = strings.TrimPrefix(t.ObjectID, req.CompanyID+"/")
			if _, known := loaded.KnownEnabled[m]; m == t.ObjectID || !known {
				writeValidationFailed(w, "company_module object "+t.ObjectID+" is not <companyId>/<module> for a known module")
				return
			}
		} else if m = loaded.TypeOwner[t.ObjectType]; m == "" {
			writeValidationFailed(w, "object type "+t.ObjectType+" is not declared by an enabled module fragment")
			return
		}
		if moduleKey != "" && m != moduleKey {
			writeValidationFailed(w, "tuples must all belong to one module (got "+moduleKey+" and "+m+")")
			return
		}
		moduleKey = m
	}
	anchorID := req.CompanyID + "/" + moduleKey

	// Write-time subject-shape validation. A non-empty subjectRelation names a USERSET subject
	// ("type#relation" — e.g. "member#mapped_user"); it must actually name a relation defined
	// on that subject type in the effective (fragment-loaded) model, or the grant would write an
	// unresolvable tuple that silently never matches at check time. Fail-closed 422, checked on
	// every tuple of a grant.
	if req.Op == "grant" {
		for _, t := range tuples {
			if t.SubjectRelation == "" {
				continue
			}
			rels, ok := loaded.Model[t.SubjectType]
			if !ok {
				writeValidationFailed(w, "subjectRelation "+t.SubjectRelation+" names unknown subject type "+t.SubjectType)
				return
			}
			if _, ok := rels[t.SubjectRelation]; !ok {
				writeValidationFailed(w, "subjectRelation "+t.SubjectRelation+" is not a relation defined on subject type "+t.SubjectType)
				return
			}
		}
	}

	// Rule 3 — the bearer passes decision steps 1–6 for (M, companyId). Denied ⇒ 403 with the
	// decision's reason, audited like a /can denial; uncertain ⇒ 503.
	d := svc.evaluate(r.Context(), decider, decision.Request{
		SubjectID: sub, FeatureKey: moduleKey + ".grants", ModuleKey: moduleKey, Scope: decision.ScopeCompany,
		CompanyID: req.CompanyID, RequiredPlatformRole: summarySuperadminRole, AllowPlatformOperatorCompanyScope: true,
		CorrelationID: req.CorrelationID,
	})
	if !d.Allowed {
		svc.auditDenial(r.Context(), sub, moduleKey+".grants", d)
		if d.Reason == decision.ReasonDependencyUnavailable {
			writeDecision(w, d)
			return
		}
		errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "grants denied: " + string(d.Reason), Details: map[string]any{"reason": string(d.Reason), "evidence": d.Evidence}})
		return
	}

	// Rules 2 and 4 — module objects are anchored at <companyId>/<M>; company_module tuples
	// need the bearer to be the module's admin.
	inRequestAnchor := map[string]bool{}
	if req.Op == "grant" {
		for _, t := range tuples {
			if t.Relation == "company_module" && t.SubjectType == "company_module" && t.SubjectID == anchorID && t.SubjectRelation == "" {
				inRequestAnchor[t.ObjectType+":"+t.ObjectID] = true
			}
		}
	}
	adminChecked := false
	for _, t := range tuples {
		if t.ObjectType == "company_module" {
			if adminChecked {
				continue
			}
			isAdmin, err := checker.Check(r.Context(), "company_module", anchorID, "admin", "user", sub)
			if err != nil {
				writeDecision(w, decision.Decision{Reason: decision.ReasonDependencyUnavailable, Dependency: "engine", Step: "grants_admin"})
				return
			}
			if !isAdmin {
				svc.auditDenial(r.Context(), sub, moduleKey+".grants", decision.Decision{Reason: decision.ReasonEngineDenied, Evidence: []decision.Evidence{{Key: "relation", Value: "admin"}, {Key: "object", Value: "company_module:" + anchorID}}})
				errenv.WriteError(w, http.StatusForbidden, errenv.APIError{Code: errenv.CodeAuthorizationDenied, Message: "grants on company_module:" + anchorID + " require its admin relation", Details: map[string]any{"reason": string(decision.ReasonEngineDenied)}})
				return
			}
			adminChecked = true
			continue
		}
		if t.Relation == "company_module" && !inRequestAnchor[t.ObjectType+":"+t.ObjectID] && req.Op == "grant" {
			writeValidationFailed(w, "company_module anchor on "+t.ObjectType+":"+t.ObjectID+" must point at company_module:"+anchorID)
			return
		}
		if inRequestAnchor[t.ObjectType+":"+t.ObjectID] {
			continue
		}
		anchored, err := checker.Check(r.Context(), t.ObjectType, t.ObjectID, "company_module", "company_module", anchorID)
		if err != nil {
			writeDecision(w, decision.Decision{Reason: decision.ReasonDependencyUnavailable, Dependency: "engine", Step: "grants_anchor"})
			return
		}
		if !anchored {
			writeValidationFailed(w, "object "+t.ObjectType+":"+t.ObjectID+" is not anchored to company_module:"+anchorID)
			return
		}
	}

	tx, err := svc.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after Commit

	var opErr error
	if req.Op == "grant" {
		opErr = store.Grant(r.Context(), tx, sub, req.CorrelationID, tuples...)
	} else {
		opErr = store.Revoke(r.Context(), tx, sub, req.CorrelationID, tuples...)
	}
	if opErr != nil {
		writeInternalError(w, opErr)
		return
	}
	if err := svc.Audit.Record(r.Context(), tx, audit.Event{
		Actor: sub, Action: "authz.grants." + req.Op, Subject: req.CorrelationID,
		Payload: map[string]any{"count": len(tuples), "companyId": req.CompanyID, "moduleKey": moduleKey}, CorrelationID: req.CorrelationID,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]any{"status": "ok", "count": len(tuples)})
}

// --- diagnostics-only raw check (never wired unless Service.DebugCheck) ---

type debugCheckWire struct {
	ObjectType  string `json:"objectType"`
	ObjectID    string `json:"objectId"`
	Relation    string `json:"relation"`
	SubjectType string `json:"subjectType"`
	SubjectID   string `json:"subjectId"`
}

func (svc *Service) handleDebugCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := svc.bearerSubject(w, r); !ok {
		return
	}
	var req debugCheckWire
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errenv.WriteError(w, http.StatusBadRequest, errenv.APIError{Code: errenv.CodeBadRequest, Message: "invalid JSON body"})
		return
	}
	en, loaded, err := svc.effectiveEngine(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	allowed, err := fragment.Check(r.Context(), en, loaded, req.ObjectType, req.ObjectID, req.Relation, req.SubjectType, req.SubjectID)
	if err != nil {
		errenv.WriteError(w, http.StatusUnprocessableEntity, errenv.APIError{Code: errenv.CodeValidationError, Message: err.Error()})
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]bool{"allowed": allowed})
}

func (svc *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (svc *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := svc.Pool.Ping(r.Context()); err != nil {
		errenv.WriteError(w, http.StatusServiceUnavailable, errenv.APIError{Code: errenv.CodeAuthorizationUnavailable, Message: "database not reachable"})
		return
	}
	errenv.WriteData(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeInternalError(w http.ResponseWriter, err error) {
	errenv.WriteError(w, http.StatusInternalServerError, errenv.APIError{Code: errenv.CodeInternalError, Message: err.Error()})
}
