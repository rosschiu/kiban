// SPDX-License-Identifier: Apache-2.0

// AuthzClient talks to authz's real effective-access decision (POST /internal/authz/
// effective-access/can and /batch-can, the pattern every module uses) plus the
// grants S2S surface (POST /internal/authz/grants, op:"grant"|"revoke") — this module's ONLY
// path to writing/removing authz tuples (modules never write authz.* tables directly). The
// can/batch-can wire shape supports an explicit object-mode check (Object+Relation), which this
// module uses as its primary access decision (docs_document owner/editor/viewer), together with
// op:"revoke" for share removal.
package docs

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// AuthzClient is modulekit's authz client plus this module's feature -> relation-leg mapping,
// its docs_document object-mode checks and its share grants.
type AuthzClient struct {
	*modulekit.AuthzClient
}

func NewAuthzClient(client *http.Client, baseURL string) *AuthzClient {
	return &AuthzClient{modulekit.NewAuthzClient(client, baseURL, "docs")}
}

type (
	authzCanRequestWire = modulekit.CanRequest
	grantsRequestWire   = modulekit.GrantsRequest
)

// docsDocumentObjectID matches the platform's object encoding exactly: <objectType>:<objectId>
// is the ENGINE'S OWN wire shape (Object{Type,ID}); the object id itself is just the document's
// own uuid — no composite needed since docs_document's tupleset parent (company_module) is
// carried by a separate tuple, not encoded into the id.
func docsDocumentObjectID(docID string) string {
	return docID
}

// relationLeg maps a FEATURE-ONLY check (docs.manage/docs.create) to the object-relation leg its
// own authz.fragment.json feature declares — never invented. docs.create carries an empty
// accessRulePayload (company-membership-gated only, same shape as timesheet's
// entries.manage-own / notification's inbox.view).
func relationLeg(featureKey string) (objectType, relation string) {
	if featureKey == "docs.manage" {
		return "company_module", "admin"
	}
	return "", ""
}

// Can asks authz's effective-access decision for a FEATURE-ONLY check (docs.manage / docs.create)
// — the ordered decision's steps 1-6 plus, for docs.manage, step 7's company_module#admin leg.
// rawBearer is forwarded verbatim (never a caller-supplied header, never re-derived).
func (c *AuthzClient) Can(ctx context.Context, rawBearer, featureKey, companyID string) (allowed bool, reason string, err error) {
	_, relation := relationLeg(featureKey)
	return c.AuthzClient.Can(ctx, rawBearer, featureKey, companyID, relation)
}

// CanObject asks authz's effective-access decision for docs's OWN object type (docs_document):
// "may THIS caller (the bearer) act as `relation` on docs_document:<docID>?" — the
// object-mode check, this module's primary access decision for every document read/write. The
// featureKey carried on the wire is informational only (audit-log labeling on a deny — see
// internal/authz/http.go's auditDenial); it never gates anything itself once Object+Relation are
// present.
func (c *AuthzClient) CanObject(ctx context.Context, rawBearer, companyID, docID, relation string) (allowed bool, reason string, err error) {
	return c.DoCan(ctx, rawBearer, modulekit.CanRequest{
		FeatureKey: "docs.document.access", ModuleKey: "docs", Scope: "company", CompanyID: companyID,
		Object: modulekit.ObjectRef{Type: "docs_document", ID: docsDocumentObjectID(docID)}, Relation: relation,
	})
}

type batchItemWire struct {
	Object   modulekit.ObjectRef `json:"object"`
	Relation string              `json:"relation"`
}

type batchCanRequestWire struct {
	modulekit.CanRequest
	Items []batchItemWire `json:"items"`
}

type batchResultWire struct {
	Object   modulekit.ObjectRef `json:"object"`
	Relation string              `json:"relation"`
	Decision modulekit.Decision  `json:"decision"`
}

type batchCanResponseWire struct {
	Data []batchResultWire `json:"data"`
}

// BatchCanObject verifies, in one round trip, whether the bearer holds `relation` on each of
// docIDs (docs_document) — used by listDocuments (belt and braces, the engine is the source of
// truth; the read-side share index is NEVER
// authoritative on its own). Returns a docID->allowed map; docIDs the response doesn't cover
// (should not happen on a well-formed response) are treated as denied — fail closed.
func (c *AuthzClient) BatchCanObject(ctx context.Context, rawBearer, companyID string, docIDs []string, relation string) (map[string]bool, error) {
	out := make(map[string]bool, len(docIDs))
	if len(docIDs) == 0 {
		return out, nil
	}
	items := make([]batchItemWire, len(docIDs))
	for i, id := range docIDs {
		items[i] = batchItemWire{Object: modulekit.ObjectRef{Type: "docs_document", ID: docsDocumentObjectID(id)}, Relation: relation}
	}
	reqWire := batchCanRequestWire{
		CanRequest: modulekit.CanRequest{FeatureKey: "docs.document.access", ModuleKey: "docs", Scope: "company", CompanyID: companyID},
		Items:      items,
	}
	var res batchCanResponseWire
	if err := c.PostJSON(ctx, rawBearer, "/internal/authz/effective-access/batch-can", "authz batch-can", reqWire, &res); err != nil {
		return nil, err
	}
	for _, r := range res.Data {
		out[r.Object.ID] = r.Decision.Allowed
	}
	for _, id := range docIDs {
		if _, ok := out[id]; !ok {
			out[id] = false // fail closed: never fabricate an allow for a missing result
		}
	}
	return out, nil
}

// GrantDocumentOwner writes `docs_document:<docID>#owner @ user:<creatorKcSub>` PLUS the
// `company_module` anchor tuple, both on document create (authz accepts the owner tuple only
// because the anchor arrives in the same request). rawBearer is the ACTING caller's own bearer;
// authz binds the write to companyID and gates it on the bearer's docs access there.
func (c *AuthzClient) GrantDocumentOwner(ctx context.Context, rawBearer, companyID, docID, creatorKcSub, correlationID string) error {
	tuples := []modulekit.Tuple{
		{ObjectType: "docs_document", ObjectID: docID, Relation: "owner", SubjectType: "user", SubjectID: creatorKcSub},
		c.AnchorTuple("docs_document", docID, companyID),
	}
	return c.GrantOrRevoke(ctx, rawBearer, companyID, "grant", tuples, correlationID)
}

// GrantShare writes `docs_document:<docID>#relation @ user:<kcSub>` (relation is "viewer" or
// "editor"); authz refuses it unless the document is anchored to companyID.
func (c *AuthzClient) GrantShare(ctx context.Context, rawBearer, companyID, docID, relation, kcSub, correlationID string) error {
	tuples := []modulekit.Tuple{{ObjectType: "docs_document", ObjectID: docID, Relation: relation, SubjectType: "user", SubjectID: kcSub}}
	return c.GrantOrRevoke(ctx, rawBearer, companyID, "grant", tuples, correlationID)
}

// RevokeShare removes `docs_document:<docID>#relation @ user:<kcSub>` — through authz's
// op:"revoke".
func (c *AuthzClient) RevokeShare(ctx context.Context, rawBearer, companyID, docID, relation, kcSub, correlationID string) error {
	tuples := []modulekit.Tuple{{ObjectType: "docs_document", ObjectID: docID, Relation: relation, SubjectType: "user", SubjectID: kcSub}}
	return c.GrantOrRevoke(ctx, rawBearer, companyID, "revoke", tuples, correlationID)
}
