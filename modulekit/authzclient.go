// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"context"
	"net/http"
)

// AuthzClient calls authz's POST /internal/authz/effective-access/can (per-operation decisions)
// and POST /internal/authz/grants (op:"grant"|"revoke") — a module's ONLY path to reading or
// writing authz tuples (modules never touch authz.* tables directly). rawBearer is always the
// acting caller's own bearer, forwarded verbatim (never a caller-supplied header, never
// re-derived); the grants endpoint binds every tuple to the request's company and gates the write
// on the bearer's access to that (module, company) — see GrantsRequest.
type AuthzClient struct {
	baseURL   string
	client    *http.Client
	moduleKey string
}

// NewAuthzClient returns a client whose requests carry moduleKey and whose errors are prefixed
// with it.
func NewAuthzClient(client *http.Client, baseURL, moduleKey string) *AuthzClient {
	return &AuthzClient{baseURL: baseURL, client: client, moduleKey: moduleKey}
}

// ModuleKey is the key given to NewAuthzClient.
func (c *AuthzClient) ModuleKey() string { return c.moduleKey }

// CompanyModuleObjectID builds the object id half of the company_module object-relation leg —
// the platform's object-id encoding "<companyId>/<moduleKey>".
func (c *AuthzClient) CompanyModuleObjectID(companyID string) string {
	return companyID + "/" + c.moduleKey
}

// AnchorTuple is the `<objectType>:<objectID>#company_module @ company_module:<companyId>/<moduleKey>`
// tuple every module object must carry (module contract §3): the decision layer binds a
// company-scope object check to the request's company through it, so an object without one
// is denied for everyone. Grant it in the same request as the object's owner tuple on create.
func (c *AuthzClient) AnchorTuple(objectType, objectID, companyID string) Tuple {
	return Tuple{
		ObjectType: objectType, ObjectID: objectID, Relation: "company_module",
		SubjectType: "company_module", SubjectID: c.CompanyModuleObjectID(companyID),
	}
}

// ObjectRef is the engine's own object wire shape.
type ObjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// CanRequest is the effective-access/can request body.
type CanRequest struct {
	FeatureKey string    `json:"featureKey"`
	ModuleKey  string    `json:"moduleKey"`
	Scope      string    `json:"scope"`
	CompanyID  string    `json:"companyId"`
	Object     ObjectRef `json:"object,omitempty"`
	Relation   string    `json:"relation,omitempty"`
}

// Decision is one allow/deny answer.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// CanResponse is the effective-access/can response envelope.
type CanResponse struct {
	Data Decision `json:"data"`
}

// Can asks authz's effective-access decision for featureKey at company scope: the ordered
// decision's steps 1-6 (subject/Keycloak/lifecycle/company-active/membership/module-enabled)
// PLUS, when relation is non-empty, step 7's company_module#<relation> object-relation leg.
// Returns (allowed, reason, nil) on a well-formed response; any transport, non-200, or decode
// failure returns a non-nil error — callers must fail closed, never treat an error as allow.
func (c *AuthzClient) Can(ctx context.Context, rawBearer, featureKey, companyID, relation string) (allowed bool, reason string, err error) {
	req := CanRequest{FeatureKey: featureKey, ModuleKey: c.moduleKey, Scope: "company", CompanyID: companyID}
	if relation != "" {
		req.Object = ObjectRef{Type: "company_module", ID: c.CompanyModuleObjectID(companyID)}
		req.Relation = relation
	}
	return c.DoCan(ctx, rawBearer, req)
}

// DoCan sends an arbitrary can request — the object-mode check on a module's own object type,
// or a position/group holder check.
func (c *AuthzClient) DoCan(ctx context.Context, rawBearer string, req CanRequest) (allowed bool, reason string, err error) {
	var out CanResponse
	if err := c.PostJSON(ctx, rawBearer, "/internal/authz/effective-access/can", "authz can", req, &out); err != nil {
		return false, "", err
	}
	return out.Data.Allowed, out.Data.Reason, nil
}

// PostJSON posts in to baseURL+path with the bearer, requiring 200 and decoding into out when
// non-nil; what names the call in error strings ("<moduleKey>: <what> request: HTTP 500").
func (c *AuthzClient) PostJSON(ctx context.Context, rawBearer, path, what string, in, out any) error {
	return postJSON(ctx, c.client, c.moduleKey, c.baseURL+path, rawBearer, what, in, out)
}

// Tuple is one relation tuple on the grants wire.
type Tuple struct {
	ObjectType      string `json:"objectType"`
	ObjectID        string `json:"objectId"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subjectType"`
	SubjectID       string `json:"subjectId"`
	SubjectRelation string `json:"subjectRelation,omitempty"`
}

// GrantsRequest is the /internal/authz/grants request body. CompanyID is the company every
// tuple is bound to: authz refuses a tuple whose object is not this company's module object
// or a module object anchored to it, and gates the write on the bearer's access to (module,
// company) — a company_module tuple additionally needs the bearer to hold its admin relation.
type GrantsRequest struct {
	Op            string  `json:"op"`
	CompanyID     string  `json:"companyId"`
	Tuples        []Tuple `json:"tuples"`
	CorrelationID string  `json:"correlationId"`
}

// GrantOrRevoke writes (op "grant") or removes (op "revoke") tuples through authz's grants API,
// bound to companyID (the request's company).
func (c *AuthzClient) GrantOrRevoke(ctx context.Context, rawBearer, companyID, op string, tuples []Tuple, correlationID string) error {
	return c.PostJSON(ctx, rawBearer, "/internal/authz/grants", "authz "+op, GrantsRequest{Op: op, CompanyID: companyID, Tuples: tuples, CorrelationID: correlationID}, nil)
}
