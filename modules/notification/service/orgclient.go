// SPDX-License-Identifier: Apache-2.0

// OrgClient reads org's membership-fact endpoint (modules consume the foundation's facts through
// APIs only — never a direct join into org's schema) to confirm a targeted event's RECIPIENT
// kcSubs are active company members before any recipient_state row is ever written for them.
package notification

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

type OrgClient struct {
	*modulekit.OrgClient
}

func NewOrgClient(client *http.Client, baseURL string) *OrgClient {
	return &OrgClient{modulekit.NewOrgClient(client, baseURL, "notification")}
}

// IsActiveMember reports whether kcSub is an ACTIVE member of companyID, per org's own membership
// fact endpoint. A transport/decode/non-200 failure returns a non-nil error — SendTargetedEvent
// treats that identically to "not a member" (skip, never deliver on an unconfirmed recipient).
func (c *OrgClient) IsActiveMember(ctx context.Context, companyID, kcSub string) (bool, error) {
	_, isMember, isActive, err := c.MemberByKcSub(ctx, companyID, kcSub)
	if err != nil {
		return false, err
	}
	return isMember && isActive, nil
}
