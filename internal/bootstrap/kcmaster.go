// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// kcMasterClient is a minimal Keycloak admin REST client authenticated as the MASTER-realm
// bootstrap admin (KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD, password grant against client_id
// admin-cli). Every OTHER service uses a realm-scoped, least-privilege service-account client
// (internal/identity/kcadmin.go's AdminClient) — this client is deliberately confined to
// internal/bootstrap, never imported elsewhere, matching that ownership rule.
type kcMasterClient struct {
	httpClient *http.Client
	baseURL    string // e.g. "http://127.0.0.1:8081" — no trailing slash
	realm      string // the APP realm this client administers (not "master")
	username   string
	password   string
}

func newKCMasterClient(httpClient *http.Client, baseURL, realm, username, password string) *kcMasterClient {
	return &kcMasterClient{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(baseURL, "/"),
		realm:      realm,
		username:   username,
		password:   password,
	}
}

func (c *kcMasterClient) token(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.username},
		"password":   {c.password},
	}
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("kcmaster: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kcmaster: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("kcmaster: token request: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kcmaster: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("kcmaster: token response had no access_token")
	}
	return out.AccessToken, nil
}

// do issues an authenticated admin-API request against the app realm's admin base
// (/admin/realms/{realm}{path}) and decodes a JSON response into out (nil to discard the body).
// Returns the HTTP status code so callers can branch on 404-vs-other without treating every
// non-2xx as fatal.
func (c *kcMasterClient) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	token, err := c.token(ctx)
	if err != nil {
		return 0, err
	}

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("kcmaster: marshal request body: %w", err)
		}
		reader = bytes.NewReader(b)
	}

	fullURL := fmt.Sprintf("%s/admin/realms/%s%s", c.baseURL, c.realm, path)
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return 0, fmt.Errorf("kcmaster: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("kcmaster: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("kcmaster: read response body: %w", err)
	}

	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("kcmaster: %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("kcmaster: decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// locationID extracts the trailing path segment (the created resource's id) from a Location
// response header — Keycloak's POST-create endpoints return 201 with no body, id in Location.
func locationIDFrom(rawLocation string) string {
	rawLocation = strings.TrimRight(rawLocation, "/")
	idx := strings.LastIndex(rawLocation, "/")
	if idx < 0 {
		return ""
	}
	return rawLocation[idx+1:]
}

// doCreate POSTs body to path and returns the created resource's id (from the Location header).
func (c *kcMasterClient) doCreate(ctx context.Context, path string, body any) (string, error) {
	token, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("kcmaster: marshal request body: %w", err)
	}
	fullURL := fmt.Sprintf("%s/admin/realms/%s%s", c.baseURL, c.realm, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("kcmaster: build create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kcmaster: POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("kcmaster: POST %s: HTTP %d: %s", path, resp.StatusCode, string(respBody))
	}
	return locationIDFrom(resp.Header.Get("Location")), nil
}

// --- client lookups ---

type kcClientRep struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Enabled                   bool              `json:"enabled"`
	Protocol                  string            `json:"protocol,omitempty"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly,omitempty"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled,omitempty"`
	RedirectUris              []string          `json:"redirectUris,omitempty"`
	WebOrigins                []string          `json:"webOrigins,omitempty"`
	Attributes                map[string]string `json:"attributes,omitempty"`
}

type kcProtocolMapperRep struct {
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name"`
	Protocol        string            `json:"protocol"`
	ProtocolMapper  string            `json:"protocolMapper"`
	ConsentRequired bool              `json:"consentRequired"`
	Config          map[string]string `json:"config"`
}

// findClientByClientID returns the client rep and its internal id ("" not found).
func (c *kcMasterClient) findClientByClientID(ctx context.Context, clientID string) (kcClientRep, bool, error) {
	var reps []kcClientRep
	_, err := c.do(ctx, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil, &reps)
	if err != nil {
		return kcClientRep{}, false, err
	}
	if len(reps) == 0 {
		return kcClientRep{}, false, nil
	}
	return reps[0], true, nil
}

func (c *kcMasterClient) createClient(ctx context.Context, rep kcClientRep) (string, error) {
	id, err := c.doCreate(ctx, "/clients", rep)
	if err != nil {
		return "", err
	}
	if id == "" {
		// Some Keycloak versions omit Location on 201 in edge cases; look it up.
		found, ok, err := c.findClientByClientID(ctx, rep.ClientID)
		if err != nil || !ok {
			return "", fmt.Errorf("kcmaster: created client %q but could not resolve its id: %w", rep.ClientID, err)
		}
		return found.ID, nil
	}
	return id, nil
}

func (c *kcMasterClient) updateClient(ctx context.Context, id string, rep kcClientRep) error {
	_, err := c.do(ctx, http.MethodPut, "/clients/"+id, rep, nil)
	return err
}

func (c *kcMasterClient) protocolMappers(ctx context.Context, clientInternalID string) ([]kcProtocolMapperRep, error) {
	var reps []kcProtocolMapperRep
	_, err := c.do(ctx, http.MethodGet, "/clients/"+clientInternalID+"/protocol-mappers/models", nil, &reps)
	return reps, err
}

func (c *kcMasterClient) createProtocolMapper(ctx context.Context, clientInternalID string, m kcProtocolMapperRep) error {
	_, err := c.doCreate(ctx, "/clients/"+clientInternalID+"/protocol-mappers/models", m)
	return err
}

func (c *kcMasterClient) updateProtocolMapper(ctx context.Context, clientInternalID, mapperID string, m kcProtocolMapperRep) error {
	_, err := c.do(ctx, http.MethodPut, "/clients/"+clientInternalID+"/protocol-mappers/models/"+mapperID, m, nil)
	return err
}

// --- realm ---

func (c *kcMasterClient) getRealm(ctx context.Context) (map[string]any, error) {
	var rep map[string]any
	_, err := c.do(ctx, http.MethodGet, "", nil, &rep)
	return rep, err
}

func (c *kcMasterClient) updateRealm(ctx context.Context, patch map[string]any) error {
	_, err := c.do(ctx, http.MethodPut, "", patch, nil)
	return err
}

// --- service account / role mappings (exact-role verification) ---

func (c *kcMasterClient) serviceAccountUserID(ctx context.Context, clientInternalID string) (string, error) {
	var rep struct {
		ID string `json:"id"`
	}
	_, err := c.do(ctx, http.MethodGet, "/clients/"+clientInternalID+"/service-account-user", nil, &rep)
	return rep.ID, err
}

type kcRoleRep struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *kcMasterClient) assignedClientRoles(ctx context.Context, userID, clientInternalID string) ([]kcRoleRep, error) {
	var reps []kcRoleRep
	_, err := c.do(ctx, http.MethodGet, "/users/"+userID+"/role-mappings/clients/"+clientInternalID, nil, &reps)
	return reps, err
}

// kcRoleMappingsRep is Keycloak's composite role-mapping view of one user: every realm role
// and, per client (keyed by clientId), every client role the user holds.
type kcRoleMappingsRep struct {
	RealmMappings  []kcRoleRep `json:"realmMappings"`
	ClientMappings map[string]struct {
		Mappings []kcRoleRep `json:"mappings"`
	} `json:"clientMappings"`
}

func (c *kcMasterClient) userRoleMappings(ctx context.Context, userID string) (kcRoleMappingsRep, error) {
	var rep kcRoleMappingsRep
	_, err := c.do(ctx, http.MethodGet, "/users/"+userID+"/role-mappings", nil, &rep)
	return rep, err
}

func (c *kcMasterClient) availableClientRoles(ctx context.Context, userID, clientInternalID string) ([]kcRoleRep, error) {
	var reps []kcRoleRep
	_, err := c.do(ctx, http.MethodGet, "/users/"+userID+"/role-mappings/clients/"+clientInternalID+"/available", nil, &reps)
	return reps, err
}

func (c *kcMasterClient) addClientRoles(ctx context.Context, userID, clientInternalID string, roles []kcRoleRep) error {
	if len(roles) == 0 {
		return nil
	}
	_, err := c.do(ctx, http.MethodPost, "/users/"+userID+"/role-mappings/clients/"+clientInternalID, roles, nil)
	return err
}

// --- secrets ---

func (c *kcMasterClient) regenerateClientSecret(ctx context.Context, clientInternalID string) (string, error) {
	var rep struct {
		Value string `json:"value"`
	}
	_, err := c.do(ctx, http.MethodPost, "/clients/"+clientInternalID+"/client-secret", nil, &rep)
	return rep.Value, err
}

func (c *kcMasterClient) clientSecret(ctx context.Context, clientInternalID string) (string, error) {
	var rep struct {
		Value string `json:"value"`
	}
	_, err := c.do(ctx, http.MethodGet, "/clients/"+clientInternalID+"/client-secret", nil, &rep)
	return rep.Value, err
}

// --- authentication flows (MFA wiring verification) ---

type kcFlowExecutionRep struct {
	ID          string `json:"id,omitempty"`
	Level       int    `json:"level"`
	Requirement string `json:"requirement"`
	ProviderID  string `json:"providerId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func (c *kcMasterClient) flowExecutions(ctx context.Context, flowAlias string) ([]kcFlowExecutionRep, error) {
	var reps []kcFlowExecutionRep
	_, err := c.do(ctx, http.MethodGet, "/authentication/flows/"+url.PathEscape(flowAlias)+"/executions", nil, &reps)
	return reps, err
}

// flowExists reports whether a top-level authentication flow with the given alias exists.
func (c *kcMasterClient) flowExists(ctx context.Context, flowAlias string) (bool, error) {
	var flows []struct {
		Alias string `json:"alias"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/authentication/flows", nil, &flows); err != nil {
		return false, err
	}
	for _, f := range flows {
		if f.Alias == flowAlias {
			return true, nil
		}
	}
	return false, nil
}

// copyFlow duplicates the flow at sourceAlias (built-in flows included — Keycloak refuses to
// edit those in place, so a copy is the only way to extend one) as a new top-level flow.
func (c *kcMasterClient) copyFlow(ctx context.Context, sourceAlias, newAlias string) error {
	_, err := c.do(ctx, http.MethodPost, "/authentication/flows/"+url.PathEscape(sourceAlias)+"/copy", map[string]string{"newName": newAlias}, nil)
	return err
}

// addFlowExecution appends the authenticator providerID as a top-level execution of flowAlias
// (Keycloak creates it DISABLED; setFlowExecutionRequirement sets the requirement).
func (c *kcMasterClient) addFlowExecution(ctx context.Context, flowAlias, providerID string) error {
	_, err := c.do(ctx, http.MethodPost, "/authentication/flows/"+url.PathEscape(flowAlias)+"/executions/execution", map[string]string{"provider": providerID}, nil)
	return err
}

func (c *kcMasterClient) setFlowExecutionRequirement(ctx context.Context, flowAlias, executionID, requirement string) error {
	_, err := c.do(ctx, http.MethodPut, "/authentication/flows/"+url.PathEscape(flowAlias)+"/executions", map[string]string{"id": executionID, "requirement": requirement}, nil)
	return err
}

// --- users (one-time superadmin) ---

type kcCredentialRep struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type kcUserRep struct {
	ID              string            `json:"id,omitempty"`
	Username        string            `json:"username"`
	Email           string            `json:"email,omitempty"`
	FirstName       string            `json:"firstName,omitempty"`
	LastName        string            `json:"lastName,omitempty"`
	Enabled         bool              `json:"enabled"`
	EmailVerified   bool              `json:"emailVerified,omitempty"`
	RequiredActions []string          `json:"requiredActions,omitempty"`
	Credentials     []kcCredentialRep `json:"credentials,omitempty"`
}

// findUserByUsername returns the user rep and true if found (Keycloak's users search endpoint
// with the `username` query param does an exact match when `exact=true`).
func (c *kcMasterClient) findUserByUsername(ctx context.Context, username string) (kcUserRep, bool, error) {
	var reps []kcUserRep
	_, err := c.do(ctx, http.MethodGet, "/users?username="+url.QueryEscape(username)+"&exact=true", nil, &reps)
	if err != nil {
		return kcUserRep{}, false, err
	}
	if len(reps) == 0 {
		return kcUserRep{}, false, nil
	}
	return reps[0], true, nil
}

// createUser creates a new realm user with a forced-temporary initial password and returns its
// Keycloak user id (the kcSub every other service keys identity by). FirstName/LastName are
// set to fixed, non-empty values: the imported realm's User Profile config (infra/keycloak-build/
// realm-kiban.json) marks both REQUIRED for role "user" — omitting them leaves Keycloak's
// VERIFY_PROFILE required action DYNAMICALLY triggered on
// every login attempt (computed from the live profile-completeness check, not from the user's
// own requiredActions list, so clearing that list doesn't help) — the resulting user could
// never complete a direct grant, and would only clear a browser login by being interactively
// prompted to fill in a profile form no batch caller can answer. A one-shot platform account has
// no independently meaningful first/last name; "Kiban"/"Superadmin" documents what it is.
func (c *kcMasterClient) createUser(ctx context.Context, username, email, tempPassword string) (string, error) {
	rep := kcUserRep{
		Username: username, Email: email, Enabled: true, EmailVerified: true,
		FirstName:       "Kiban",
		LastName:        "Superadmin",
		RequiredActions: []string{"UPDATE_PASSWORD"},
		Credentials:     []kcCredentialRep{{Type: "password", Value: tempPassword, Temporary: true}},
	}
	id, err := c.doCreate(ctx, "/users", rep)
	if err != nil {
		return "", err
	}
	if id == "" {
		found, ok, err := c.findUserByUsername(ctx, username)
		if err != nil || !ok {
			return "", fmt.Errorf("kcmaster: created user %q but could not resolve its id: %w", username, err)
		}
		return found.ID, nil
	}
	return id, nil
}
