// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrOrgMemberNotFound is GetMember's 404, returned wrapped as "<moduleKey>: org member not
// found"; match with errors.Is.
var ErrOrgMemberNotFound = errors.New("org member not found")

// OrgClient calls org's internal, unauthenticated-at-that-layer member-facts endpoints (modules
// consume the foundation's facts through APIs only — never a direct join into org's schema).
type OrgClient struct {
	baseURL string
	client  *http.Client
	prefix  string

	errMemberNotFound error
}

// NewOrgClient returns a client whose errors are prefixed with moduleKey.
func NewOrgClient(client *http.Client, baseURL, moduleKey string) *OrgClient {
	return &OrgClient{baseURL: baseURL, client: client, prefix: moduleKey, errMemberNotFound: fmt.Errorf("%s: %w", moduleKey, ErrOrgMemberNotFound)}
}

// OrgMember is a member's own facts as org's GET /internal/org/members/{id} reports them.
type OrgMember struct {
	ID          string
	CompanyID   string
	DisplayName string
	IsActive    bool
	KcSub       string // "" if the member has no linked user account
}

// MemberByKcSub resolves a kcSub's own org member row within companyID — mirrors org's
// handleMemberByKcSub response shape exactly.
func (c *OrgClient) MemberByKcSub(ctx context.Context, companyID, kcSub string) (memberID string, isMember, isActive bool, err error) {
	var out struct {
		Data struct {
			IsMember bool    `json:"isMember"`
			IsActive bool    `json:"isActive"`
			MemberID *string `json:"memberId"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/internal/org/companies/%s/members/by-kcsub/%s", url.PathEscape(companyID), url.PathEscape(kcSub))
	if err := c.GetJSON(ctx, path, "member-by-kcsub", &out, nil); err != nil {
		return "", false, false, err
	}
	if out.Data.MemberID != nil {
		memberID = *out.Data.MemberID
	}
	return memberID, out.Data.IsMember, out.Data.IsActive, nil
}

// GetMember returns a member's own facts (including its linked user's kcSub, if any). A 404 is
// ErrOrgMemberNotFound (wrapped).
func (c *OrgClient) GetMember(ctx context.Context, memberID string) (OrgMember, error) {
	var out struct {
		Data struct {
			ID          string `json:"id"`
			CompanyID   string `json:"companyId"`
			DisplayName string `json:"displayName"`
			IsActive    bool   `json:"isActive"`
			User        *struct {
				KcSub string `json:"kcSub"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := c.GetJSON(ctx, "/internal/org/members/"+url.PathEscape(memberID), "get-member", &out, c.errMemberNotFound); err != nil {
		return OrgMember{}, err
	}
	m := OrgMember{ID: out.Data.ID, CompanyID: out.Data.CompanyID, DisplayName: out.Data.DisplayName, IsActive: out.Data.IsActive}
	if out.Data.User != nil {
		m.KcSub = out.Data.User.KcSub
	}
	return m, nil
}

// GetJSON reads baseURL+path into out, requiring 200; a 404 returns notFound when non-nil. what
// names the call in error strings ("<moduleKey>: <what>: HTTP 500").
func (c *OrgClient) GetJSON(ctx context.Context, path, what string, out any, notFound error) error {
	return getJSON(ctx, c.client, c.prefix, c.baseURL+path, what, out, notFound)
}
