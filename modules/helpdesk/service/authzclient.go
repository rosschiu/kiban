// SPDX-License-Identifier: Apache-2.0

// AuthzClient calls authz's POST /internal/authz/effective-access/can (per-operation decisions,
// the pattern every module uses) plus POST /internal/authz/grants (agent designation: this
// module's agents API wraps the existing grants surface, never a parallel grant store). company_module#editor (the agent tier) and
// company_module#admin are both BASE MODEL relations (internal/authz/engine/model.json) —
// referenced only, never redeclared in authz.fragment.json's own `relations` (there are none —
// see the fragment's own _comment). This is deliberately the OTHER authz idiom from docs: no
// object-mode checks here at all, only feature/tier checks against the company_module anchor —
// per-ticket visibility is plain service-logic row comparison (see http.go), never an engine
// call.
package helpdesk

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// AuthzClient is modulekit's authz client plus this module's feature -> relation-leg mapping,
// its position/group holder checks and its agent-tier grants.
type AuthzClient struct {
	*modulekit.AuthzClient
}

func NewAuthzClient(client *http.Client, baseURL string) *AuthzClient {
	return &AuthzClient{modulekit.NewAuthzClient(client, baseURL, "helpdesk")}
}

type (
	authzCanRequestWire = modulekit.CanRequest
	grantsRequestWire   = modulekit.GrantsRequest
	tupleWire           = modulekit.Tuple
)

func companyModuleObjectID(companyID string) string {
	return companyID + "/helpdesk"
}

// relationLeg mirrors authz.fragment.json's features[].accessRulePayload's INTENT, but is the
// mechanism that actually governs the wire request — same established precedent as
// modules/timesheet/service/authzclient.go's own relationLeg (the fragment JSON's
// accessRulePayload is documentary; this hardcoded mapping is what's actually sent).
// helpdesk.tickets.create carries no relation leg (company-membership-gated only, same shape as
// docs.create/timesheet.entries.manage-own).
func relationLeg(featureKey string) (objectType, relation string) {
	switch featureKey {
	case featureHelpdeskManage:
		return "company_module", "admin"
	case featureTicketsWork:
		return "company_module", "editor"
	default: // featureTicketsCreate
		return "", ""
	}
}

// Can asks authz's effective-access decision for a company_module-tier feature check
// (helpdesk.manage / helpdesk.tickets.work / helpdesk.tickets.create). rawBearer is forwarded
// verbatim (never a caller-supplied header, never re-derived).
func (c *AuthzClient) Can(ctx context.Context, rawBearer, featureKey, companyID string) (allowed bool, reason string, err error) {
	_, relation := relationLeg(featureKey)
	return c.AuthzClient.Can(ctx, rawBearer, featureKey, companyID, relation)
}

// IsPositionHolder is an OBJECT-MODE check (the OTHER authz idiom this module uses,
// alongside the tier checks above): "does the caller currently hold position
// <positionID>?" — position:<positionID>#holder @ user:<callerKcSub>, resolved via the SAME
// object-mode `can` wire docs's own CanObject uses, engine walking the position
// chain (holder -> member.mapped_user -> user). This is the mechanism DOING the work for "is the
// caller the assignee?" on a position-assigned ticket — never a duplicated org holder lookup, no
// read-side authority (never a decision from the read-side index alone).
// featureKey is informational only (audit-log labeling on a deny), same posture as docs's own
// CanObject — helpdesk.tickets.work is reused since it's the closest-meaning already-declared
// feature key, never invented fresh for this call.
func (c *AuthzClient) IsPositionHolder(ctx context.Context, rawBearer, companyID, positionID string) (allowed bool, err error) {
	allowed, _, err = c.DoCan(ctx, rawBearer, modulekit.CanRequest{
		FeatureKey: featureTicketsWork, ModuleKey: "helpdesk", Scope: "company", CompanyID: companyID,
		Object: modulekit.ObjectRef{Type: "position", ID: positionID}, Relation: "holder",
	})
	return allowed, err
}

// IsGroupMember is IsPositionHolder's group sibling: "is the caller currently a MEMBER of
// group <groupID>?" — group:<groupID>#member @ user:<callerKcSub>, resolved via the SAME
// object-mode `can` wire, engine walking the group chain (member -> member.mapped_user -> user).
// The mechanism doing the work for "is the caller an assignee?" on a group-assigned ticket —
// never a duplicated org membership lookup.
func (c *AuthzClient) IsGroupMember(ctx context.Context, rawBearer, companyID, groupID string) (allowed bool, err error) {
	allowed, _, err = c.DoCan(ctx, rawBearer, modulekit.CanRequest{
		FeatureKey: featureTicketsWork, ModuleKey: "helpdesk", Scope: "company", CompanyID: companyID,
		Object: modulekit.ObjectRef{Type: "group", ID: groupID}, Relation: "member",
	})
	return allowed, err
}

func (c *AuthzClient) grantOrRevoke(ctx context.Context, rawBearer, op, relation, kcSub, companyID, correlationID string) error {
	return c.grantOrRevokeTuple(ctx, rawBearer, companyID, op, tupleWire{
		ObjectType: "company_module", ObjectID: companyModuleObjectID(companyID), Relation: relation,
		SubjectType: "user", SubjectID: kcSub,
	}, correlationID)
}

// grantOrRevokePosition is grantOrRevoke's position sibling: the subject is a POSITION userset
// (`position:<id>#holder`), not a plain user — the mechanism (position:<id>#holder
// @ member:<id>#mapped_user @ user:<kcSub>) is what lets a successor inherit the tier with zero
// permission edits on handover, because this tuple never names a kcSub at all.
func (c *AuthzClient) grantOrRevokePosition(ctx context.Context, rawBearer, op, relation, positionID, companyID, correlationID string) error {
	return c.grantOrRevokeTuple(ctx, rawBearer, companyID, op, tupleWire{
		ObjectType: "company_module", ObjectID: companyModuleObjectID(companyID), Relation: relation,
		SubjectType: "position", SubjectID: positionID, SubjectRelation: "holder",
	}, correlationID)
}

// grantOrRevokeGroup is grantOrRevokePosition's group sibling: the subject is a GROUP
// userset (`group:<id>#member`) — the same mechanism (group:<id>#member @ member:<id>#mapped_user
// @ user:<kcSub>) lets every current member of the group inherit the tier, and membership changes
// (add/remove) flip who holds it with zero permission edits on this side.
func (c *AuthzClient) grantOrRevokeGroup(ctx context.Context, rawBearer, op, relation, groupID, companyID, correlationID string) error {
	return c.grantOrRevokeTuple(ctx, rawBearer, companyID, op, tupleWire{
		ObjectType: "company_module", ObjectID: companyModuleObjectID(companyID), Relation: relation,
		SubjectType: "group", SubjectID: groupID, SubjectRelation: "member",
	}, correlationID)
}

func (c *AuthzClient) grantOrRevokeTuple(ctx context.Context, rawBearer, companyID, op string, tuple tupleWire, correlationID string) error {
	return c.GrantOrRevoke(ctx, rawBearer, companyID, op, []tupleWire{tuple}, correlationID)
}

// GrantAgent writes `company_module:<companyId>/helpdesk#editor @ user:<kcSub>` through authz's
// own /internal/authz/grants (this module's agents API wraps it, never a parallel grant store —
// the same approach timesheet's approvers API takes, here for the AGENT tier). rawBearer is the
// ADMIN caller's own bearer (the one withAuth already verified holds helpdesk.manage); authz
// re-checks that the bearer holds `company_module:<companyId>/helpdesk#admin` before writing.
func (c *AuthzClient) GrantAgent(ctx context.Context, rawBearer, companyID, kcSub, correlationID string) error {
	return c.grantOrRevoke(ctx, rawBearer, "grant", "editor", kcSub, companyID, correlationID)
}

// RevokeAgent removes `company_module:<companyId>/helpdesk#editor @ user:<kcSub>` — the agent-
// removal action, gated by the module's own last-ticket-assignment protection rule (http.go)
// BEFORE this is ever called.
func (c *AuthzClient) RevokeAgent(ctx context.Context, rawBearer, companyID, kcSub, correlationID string) error {
	return c.grantOrRevoke(ctx, rawBearer, "revoke", "editor", kcSub, companyID, correlationID)
}

// GrantPositionAgent writes `company_module:<companyId>/helpdesk#editor @ position:<id>#holder`
// — binds the agent tier to a POSITION rather than a member. authz's own write-time
// subject-shape validation requires `holder` to be a relation the base model declares
// on type `position`, which it does (internal/authz/harness/model.fga).
func (c *AuthzClient) GrantPositionAgent(ctx context.Context, rawBearer, companyID, positionID, correlationID string) error {
	return c.grantOrRevokePosition(ctx, rawBearer, "grant", "editor", positionID, companyID, correlationID)
}

// RevokePositionAgent removes `company_module:<companyId>/helpdesk#editor @ position:<id>#holder`.
func (c *AuthzClient) RevokePositionAgent(ctx context.Context, rawBearer, companyID, positionID, correlationID string) error {
	return c.grantOrRevokePosition(ctx, rawBearer, "revoke", "editor", positionID, companyID, correlationID)
}

// GrantGroupAgent writes `company_module:<companyId>/helpdesk#editor @ group:<id>#member`
// — binds the agent tier to a GROUP rather than a member or position. authz's own
// write-time subject-shape validation requires `member` to be a relation the base model declares
// on type `group`, which it does (internal/authz/harness/model.fga).
func (c *AuthzClient) GrantGroupAgent(ctx context.Context, rawBearer, companyID, groupID, correlationID string) error {
	return c.grantOrRevokeGroup(ctx, rawBearer, "grant", "editor", groupID, companyID, correlationID)
}

// RevokeGroupAgent removes `company_module:<companyId>/helpdesk#editor @ group:<id>#member`.
func (c *AuthzClient) RevokeGroupAgent(ctx context.Context, rawBearer, companyID, groupID, correlationID string) error {
	return c.grantOrRevokeGroup(ctx, rawBearer, "revoke", "editor", groupID, companyID, correlationID)
}
