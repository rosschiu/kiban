// SPDX-License-Identifier: Apache-2.0

// notification's per-operation authorization goes through authz's real effective-access decision
// (POST /internal/authz/effective-access/can), with the fragment's own object-relation leg (step 7
// of the ordered decision) for the two tiers that need it. `channels.manage`/`messages.send` anchor
// on `company_module#admin` (authz.fragment.json's own accessRulePayload), resolvable because every
// (company, module) pair gets a default `company_module:<companyId>/<moduleKey>#system
// @ system:platform` structural tuple. `inbox.view` carries NO relation leg: its fragment anchors on
// `company_module#member`, which does not exist on the base model's `company_module` type
// (internal/authz/engine/model.json only defines system/company/admin/editor/submitter/approver/viewer)
// — wiring it literally would engine-error (UNKNOWN_RELATION) for every caller. inbox.view is
// therefore gated by the ordered decision's steps 1-6 (company-membership-based), never
// relation-gated.
package notification

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// AuthzClient is modulekit's authz client plus this module's feature -> relation-leg mapping.
type AuthzClient struct {
	*modulekit.AuthzClient
}

func NewAuthzClient(client *http.Client, baseURL string) *AuthzClient {
	return &AuthzClient{modulekit.NewAuthzClient(client, baseURL, "notification")}
}

type authzCanRequestWire = modulekit.CanRequest

// relationLeg maps featureKey to the object-relation leg its OWN authz.fragment.json feature
// declares (accessRulePayload), or ("", "") for a feature that carries none (inbox.view — see
// this file's header comment). Never invented: this mirrors authz.fragment.json's features[]
// exactly.
func relationLeg(featureKey string) (objectType, relation string) {
	switch featureKey {
	case featureChannelsManage, featureMessagesSend:
		return "company_module", "admin"
	default:
		return "", ""
	}
}

// Can asks authz's effective-access decision for featureKey at company scope, adding the
// company_module relation leg relationLeg declares for it. rawBearer is forwarded verbatim (the
// SAME bearer withAuth already verified itself). Any transport, non-200, or decode failure
// returns a non-nil error — callers must fail closed, never treat an error as allow.
func (c *AuthzClient) Can(ctx context.Context, rawBearer, featureKey, companyID string) (allowed bool, reason string, err error) {
	_, relation := relationLeg(featureKey)
	return c.AuthzClient.Can(ctx, rawBearer, featureKey, companyID, relation)
}

// GrantChannelAnchor writes `notification_channel:<channelID>#company_module @
// company_module:<companyID>/notification` on channel create — the anchor the fragment's
// `notification_channel.company_module` relation declares and the decision layer binds object
// checks through.
func (c *AuthzClient) GrantChannelAnchor(ctx context.Context, rawBearer, companyID, channelID string) error {
	return c.GrantOrRevoke(ctx, rawBearer, companyID, "grant", []modulekit.Tuple{c.AnchorTuple("notification_channel", channelID, companyID)}, channelID)
}
