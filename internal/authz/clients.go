// SPDX-License-Identifier: Apache-2.0

// Package authz wires the authz service: the fragment-loaded engine, the transactional grant
// store, the effective-access decision, and their HTTP surface. This file holds the real
// (non-faked) Deps implementations — small HTTP clients against identity/registry's existing
// internal endpoints, following org's internal/org/identityclient.go pattern (validates over
// HTTP, not by trusting input). Every request-body value that lands in a URL path is
// url.PathEscape'd, so a companyId of "x/state?y" is one path segment,
// never a different endpoint.
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
)

// IdentityClient calls identity's GET /internal/identity/users/{kcSub}/state. It answers
// BOTH decision.SubjectSource (step 1/3: lifecycle) and decision.KeycloakSource (step 2:
// kcEnabled), since both ride the same response. The platform role is NOT identity's to answer
// (enginePlatformRoleSource below).
type IdentityClient struct {
	HTTP    *http.Client
	BaseURL string
}

func NewIdentityClient(client *http.Client, baseURL string) *IdentityClient {
	return &IdentityClient{HTTP: client, BaseURL: baseURL}
}

type userStateResponse struct {
	Data struct {
		Lifecycle string `json:"lifecycle"`
		KCEnabled string `json:"kcEnabled"`
	} `json:"data"`
}

func (c *IdentityClient) fetchState(ctx context.Context, subjectID string) (userStateResponse, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/identity/users/"+url.PathEscape(subjectID)+"/state", nil)
	if err != nil {
		return userStateResponse{}, false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return userStateResponse{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return userStateResponse{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return userStateResponse{}, false, fmt.Errorf("identity: GET user state: HTTP %d", resp.StatusCode)
	}
	var out userStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return userStateResponse{}, false, fmt.Errorf("identity: decode user state: %w", err)
	}
	return out, true, nil
}

// Lookup implements decision.SubjectSource (step 1/3).
func (c *IdentityClient) Lookup(ctx context.Context, subjectID string) (decision.SubjectResult, error) {
	st, found, err := c.fetchState(ctx, subjectID)
	if err != nil {
		return decision.SubjectResult{}, err
	}
	if !found {
		return decision.SubjectResult{Found: false}, nil
	}
	return decision.SubjectResult{Found: true, LifecycleActive: st.Data.Lifecycle == "active"}, nil
}

// Enabled implements decision.KeycloakSource (step 2). identity's kcEnabled is itself a
// tri-state string ("true"/"false"/"unknown" — see internal/identity/state.go); never
// defaulted to enabled on ambiguity.
func (c *IdentityClient) Enabled(ctx context.Context, subjectID string) (decision.KCState, error) {
	st, found, err := c.fetchState(ctx, subjectID)
	if err != nil {
		return decision.KCUnknown, err
	}
	if !found {
		return decision.KCUnknown, nil
	}
	switch st.Data.KCEnabled {
	case "true":
		return decision.KCTrue, nil
	case "false":
		return decision.KCFalse, nil
	default:
		return decision.KCUnknown, nil
	}
}

// enginePlatformRoleSource implements decision.PlatformRoleSource (step 4 and the step-5
// operator exception) as an engine check on the platform role's one record, the tuple
// `system:platform#superadmin @ user:<subjectID>` (the same fragment-aware EngineChecker step 7
// uses). kiban-superadmin is the only platform role: any other role string is simply not held
// (false, never an error). A live DB read on every call — never a JWT claim, never cached.
type enginePlatformRoleSource struct {
	checker decision.EngineChecker
}

func (s enginePlatformRoleSource) HasRole(ctx context.Context, subjectID, role string) (bool, error) {
	if role != store.PlatformRoleSuperadmin {
		return false, nil
	}
	tp := store.SuperadminTuple(subjectID)
	return s.checker.Check(ctx, tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID)
}

// RegistryClient calls registry's GET /api/platform/capabilities/{module} for
// decision.ModuleStateSource (step 6).
type RegistryClient struct {
	HTTP    *http.Client
	BaseURL string
}

func NewRegistryClient(client *http.Client, baseURL string) *RegistryClient {
	return &RegistryClient{HTTP: client, BaseURL: baseURL}
}

type capabilityResponse struct {
	Data struct {
		Enabled bool `json:"enabled"`
	} `json:"data"`
}

// Enabled implements decision.ModuleStateSource.
func (c *RegistryClient) Enabled(ctx context.Context, moduleKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/platform/capabilities/"+url.PathEscape(moduleKey), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil // not in the catalog at all ⇒ not enabled (MODULE_DISABLED covers both)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("registry: GET capability: HTTP %d", resp.StatusCode)
	}
	var out capabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("registry: decode capability: %w", err)
	}
	return out.Data.Enabled, nil
}

type capabilitiesListResponse struct {
	Data []struct {
		Module  string `json:"module"`
		Enabled bool   `json:"enabled"`
	} `json:"data"`
}

// KnownEnabled calls registry's GET /api/platform/capabilities to build the module_key -> true
// set fragment.Load needs (only registry-known, enabled modules' fragments merge into
// the effective model).
func (c *RegistryClient) KnownEnabled(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/platform/capabilities", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry: GET capabilities: HTTP %d", resp.StatusCode)
	}
	var out capabilitiesListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("registry: decode capabilities: %w", err)
	}
	known := make(map[string]bool, len(out.Data))
	for _, m := range out.Data {
		known[m.Module] = m.Enabled
	}
	return known, nil
}

// OrgClient calls org's internal company-facts endpoints — implements
// decision.CompanySource and decision.MembershipSource end-to-end. Both endpoints are open
// internal reads (no bearer required org-side, same shape as identity's own
// GET /internal/identity/users/{kcSub}/state) since they answer pure
// facts, not user-facing data; the effective-access endpoint itself is the bearer-gated boundary.
type OrgClient struct {
	HTTP    *http.Client
	BaseURL string
}

func NewOrgClient(client *http.Client, baseURL string) *OrgClient {
	return &OrgClient{HTTP: client, BaseURL: baseURL}
}

type companyStateResponse struct {
	Data struct {
		Exists   bool `json:"exists"`
		IsActive bool `json:"isActive"`
	} `json:"data"`
}

// State implements decision.CompanySource (step 5) via
// GET /internal/org/companies/{companyID}/state. Any transport/decode failure or non-200 status
// is a genuine dependency failure (⇒ DEPENDENCY_UNAVAILABLE) — never defaulted to
// exists/isActive=true.
func (c *OrgClient) State(ctx context.Context, companyID string) (decision.CompanyState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/org/companies/"+url.PathEscape(companyID)+"/state", nil)
	if err != nil {
		return decision.CompanyState{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return decision.CompanyState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decision.CompanyState{}, fmt.Errorf("org: GET company state: HTTP %d", resp.StatusCode)
	}
	var out companyStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return decision.CompanyState{}, fmt.Errorf("org: decode company state: %w", err)
	}
	return decision.CompanyState{Exists: out.Data.Exists, Active: out.Data.IsActive}, nil
}

type membershipResponse struct {
	Data struct {
		IsMember bool    `json:"isMember"`
		MemberID *string `json:"memberId"`
		IsActive bool    `json:"isActive"`
	} `json:"data"`
}

// Membership implements decision.MembershipSource (step 5) via
// GET /internal/org/companies/{companyID}/members/by-kcsub/{subjectID}. Membership is real (a
// linked member row exists); Blocked = COMPANY_ACCESS_BLOCKED's v1 source, `member.is_active =
// false` on an existing membership — never derived any other way.
func (c *OrgClient) Membership(ctx context.Context, companyID, subjectID string) (decision.MembershipState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/internal/org/companies/"+url.PathEscape(companyID)+"/members/by-kcsub/"+url.PathEscape(subjectID), nil)
	if err != nil {
		return decision.MembershipState{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return decision.MembershipState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decision.MembershipState{}, fmt.Errorf("org: GET membership: HTTP %d", resp.StatusCode)
	}
	var out membershipResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return decision.MembershipState{}, fmt.Errorf("org: decode membership: %w", err)
	}
	if !out.Data.IsMember {
		return decision.MembershipState{IsMember: false}, nil
	}
	return decision.MembershipState{IsMember: true, Blocked: !out.Data.IsActive}, nil
}

// engineCompanyRoleSource implements decision.CompanyRoleSource (step 5's COMPANY_ROLE_REQUIRED
// leg) as a v1 engine tuple check on `company:<id>` relations (org exposes no role endpoint —
// roles live as tuples, not org rows) — authz-side only, the same
// EngineChecker the step-7 relation check already uses.
type engineCompanyRoleSource struct {
	checker decision.EngineChecker
}

// HasRole checks the `company:<companyID>#<role>` relation for `user:<subjectID>` (e.g. the
// model's `company#admin` relation: `[user] or admin from company or superadmin from system`).
func (s engineCompanyRoleSource) HasRole(ctx context.Context, companyID, subjectID, role string) (bool, error) {
	return s.checker.Check(ctx, "company", companyID, role, "user", subjectID)
}
