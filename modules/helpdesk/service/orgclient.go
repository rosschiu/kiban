// SPDX-License-Identifier: Apache-2.0

// OrgClient reads org's member/position/group facts (modules consume the foundation's facts
// through APIs only — never a direct join into org's schema): the caller's own member id (to
// record as reporter), a target assignee/agent's memberId resolved to its linked user's kcSub,
// and the position/group facts the agent-binding paths need.
package helpdesk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rosschiu/kiban/modulekit"
)

type OrgClient struct {
	*modulekit.OrgClient
}

func NewOrgClient(client *http.Client, baseURL string) *OrgClient {
	return &OrgClient{modulekit.NewOrgClient(client, baseURL, "helpdesk")}
}

// OrgPosition is a position's own facts (read through org's API, never a direct join into org's
// schema) — the position-binding path needs companyId (to
// validate the binding stays within the caller's own company) and title (the position_title
// snapshot helpdesk.agent stores for display).
type OrgPosition struct {
	ID        string
	CompanyID string
	Title     string
}

var ErrOrgPositionNotFound = fmt.Errorf("helpdesk: org position not found")

// GetPosition returns a position's own facts — used to resolve a bind-agent-to-position request's
// positionId to its companyId (the 422 company-mismatch check) and title (the display snapshot).
func (c *OrgClient) GetPosition(ctx context.Context, positionID string) (OrgPosition, error) {
	var out struct {
		Data struct {
			ID        string `json:"id"`
			CompanyID string `json:"companyId"`
			Title     string `json:"title"`
		} `json:"data"`
	}
	if err := c.GetJSON(ctx, "/internal/org/positions/"+url.PathEscape(positionID), "get-position", &out, ErrOrgPositionNotFound); err != nil {
		return OrgPosition{}, err
	}
	return OrgPosition{ID: out.Data.ID, CompanyID: out.Data.CompanyID, Title: out.Data.Title}, nil
}

// errHolderUnassigned is GetPositionHolder's 404 marker — mapped to (ok=false, nil).
var errHolderUnassigned = errors.New("helpdesk: position holder unassigned")

// GetPositionHolder resolves TODAY's holder of a position via org's own S2S holder-on-date read
// (GET /internal/org/positions/{id}/holder?date=YYYY-MM-DD) — used ONLY for display (assigneeDisplayName) and notification recipient resolution,
// NEVER for authorization (that is exclusively AuthzClient.IsPositionHolder's job — never a
// decision from the read-side index alone). ok=false (no error) means the
// chair is currently unassigned — a legitimate, non-error state (an unassigned chair means no
// recipient, no error).
func (c *OrgClient) GetPositionHolder(ctx context.Context, positionID string) (memberID string, ok bool, err error) {
	today := time.Now().UTC().Format("2006-01-02")
	var out struct {
		Data struct {
			MemberID string `json:"memberId"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/internal/org/positions/%s/holder?date=%s", url.PathEscape(positionID), today)
	if err := c.GetJSON(ctx, path, "get-position-holder", &out, errHolderUnassigned); err != nil {
		if errors.Is(err, errHolderUnassigned) {
			return "", false, nil // unassigned chair — not an error
		}
		return "", false, err
	}
	if out.Data.MemberID == "" {
		return "", false, nil
	}
	return out.Data.MemberID, true, nil
}

// OrgGroup is a group's own facts (read through org's API, never a direct join into org's
// schema) — the group-binding path needs companyId (to validate
// the binding stays within the caller's own company) and name (the group_title snapshot
// helpdesk.agent/helpdesk.ticket store for display), mirroring OrgPosition.
type OrgGroup struct {
	ID             string
	CompanyID      string
	Name           string
	IsKibanManaged bool
}

var ErrOrgGroupNotFound = fmt.Errorf("helpdesk: org group not found")

// GetGroup returns a group's own facts — used to resolve a bind-agent-to-group/assign-to-group
// request's groupId to its companyId (the 422 company-mismatch check) and name (the display
// snapshot). Calls org's S2S read, GET /internal/org/groups/{id}.
func (c *OrgClient) GetGroup(ctx context.Context, groupID string) (OrgGroup, error) {
	var out struct {
		Data struct {
			ID             string `json:"id"`
			CompanyID      string `json:"companyId"`
			Name           string `json:"name"`
			IsKibanManaged bool   `json:"isKibanManaged"`
		} `json:"data"`
	}
	if err := c.GetJSON(ctx, "/internal/org/groups/"+url.PathEscape(groupID), "get-group", &out, ErrOrgGroupNotFound); err != nil {
		return OrgGroup{}, err
	}
	return OrgGroup{ID: out.Data.ID, CompanyID: out.Data.CompanyID, Name: out.Data.Name, IsKibanManaged: out.Data.IsKibanManaged}, nil
}

// OrgGroupMember is one current member of a group — used for the notification fan-out a
// group-assigned ticket needs (unlike a position's single holder, EVERY current member with a
// linked user gets notified). Org's own group-members read doesn't carry kcSub (least disclosure —
// see internal/org/http.go's groupMemberView), so
// resolving a member's linked user for notification is a SEPARATE GetMember call per member, the
// same one-round-trip-per-recipient pattern GetPositionHolder+GetMember already establishes.
type OrgGroupMember struct {
	MemberID string
}

// ListGroupMembers resolves a group's CURRENT members via org's own S2S read (GET
// /internal/org/groups/{id}/members) — used ONLY for display/notification-recipient resolution,
// NEVER for authorization (that is exclusively AuthzClient.IsGroupMember's job — the same
// "never a decision from the read-side index alone" posture GetPositionHolder documents). An
// empty result is a legitimate, non-error state (an empty group has no notification recipients).
func (c *OrgClient) ListGroupMembers(ctx context.Context, groupID string) ([]OrgGroupMember, error) {
	var out struct {
		Data []struct {
			MemberID string `json:"memberId"`
		} `json:"data"`
	}
	if err := c.GetJSON(ctx, "/internal/org/groups/"+url.PathEscape(groupID)+"/members", "list-group-members", &out, nil); err != nil {
		return nil, err
	}
	members := make([]OrgGroupMember, 0, len(out.Data))
	for _, m := range out.Data {
		members = append(members, OrgGroupMember{MemberID: m.MemberID})
	}
	return members, nil
}
