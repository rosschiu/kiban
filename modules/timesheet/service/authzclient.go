// SPDX-License-Identifier: Apache-2.0

// AuthzClient calls authz's POST /internal/authz/effective-access/can (per-operation decisions)
// and POST /internal/authz/grants (submitter/approver designation — this module's approvers API
// wraps the existing grants surface, never a parallel grant store). Both company_module#submitter
// and company_module#approver are BASE MODEL relations (internal/authz/engine/model.json) —
// referenced only, never redeclared in authz.fragment.json's own `relations` (there are none —
// see the fragment's own _comment).
package timesheet

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// AuthzClient is modulekit's authz client plus this module's feature -> relation-leg mapping
// and its approver/submitter grant.
type AuthzClient struct {
	*modulekit.AuthzClient
}

func NewAuthzClient(client *http.Client, baseURL string) *AuthzClient {
	return &AuthzClient{modulekit.NewAuthzClient(client, baseURL, "timesheet")}
}

type (
	authzCanRequestWire = modulekit.CanRequest
	grantsRequestWire   = modulekit.GrantsRequest
)

// relationLeg mirrors authz.fragment.json's features[].accessRulePayload exactly — never
// invented. entries.manage-own carries a payload (relation "member") the base model doesn't
// define (same as notification's inbox.view), so it stays membership-gated only, same as
// notification's own handling.
func relationLeg(featureKey string) (objectType, relation string) {
	switch featureKey {
	case featureProjectsManage, featureConfigManage, featureApproversManage:
		return "company_module", "admin"
	case featureSubmissionsSubmit:
		return "company_module", "submitter"
	case featureSubmissionsApprove:
		return "company_module", "approver"
	default: // featureEntriesManageOwn
		return "", ""
	}
}

func (c *AuthzClient) Can(ctx context.Context, rawBearer, featureKey, companyID string) (allowed bool, reason string, err error) {
	_, relation := relationLeg(featureKey)
	return c.AuthzClient.Can(ctx, rawBearer, featureKey, companyID, relation)
}

// GrantRelation writes `company_module:<companyId>/timesheet#relation @ user:<kcSub>` through
// authz's own /internal/authz/grants (this module's approvers API wraps it, never a parallel grant
// store). rawBearer is the ADMIN caller's own bearer (the one withAuth already verified holds
// timesheet.approvers.manage); authz re-checks that the bearer holds
// `company_module:<companyId>/timesheet#admin` before writing.
func (c *AuthzClient) GrantRelation(ctx context.Context, rawBearer, companyID, relation, kcSub, correlationID string) error {
	return c.GrantOrRevoke(ctx, rawBearer, companyID, "grant", []modulekit.Tuple{{
		ObjectType: "company_module", ObjectID: c.CompanyModuleObjectID(companyID), Relation: relation,
		SubjectType: "user", SubjectID: kcSub,
	}}, correlationID)
}
