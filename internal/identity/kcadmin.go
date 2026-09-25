// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// KCStateTrue/False/Unknown are the tri-state kcEnabled values the state endpoint reports:
// live-queried from Keycloak on every call, and NEVER defaulted to enabled on error
// (fail-closed feeds DEPENDENCY_UNAVAILABLE at the effective-access layer).
const (
	KCStateTrue    = "true"
	KCStateFalse   = "false"
	KCStateUnknown = "unknown"
)

// AdminClient talks to the Keycloak admin REST API using a dedicated service-account client
// (client_credentials against the app realm — never master-realm credentials). Plain net/http
// against the admin REST API; no Keycloak client library.
type AdminClient struct {
	httpClient   *http.Client
	baseURL      string // e.g. "http://127.0.0.1:8081" — no trailing slash
	realm        string
	clientID     string
	clientSecret string
}

// NewAdminClient builds an AdminClient. httpClient's Timeout governs both the token fetch and
// the admin API call — a slow/unreachable Keycloak must fail fast into the "unknown" state
// rather than hang the caller.
func NewAdminClient(httpClient *http.Client, baseURL, realm, clientID, clientSecret string) *AdminClient {
	return &AdminClient{
		httpClient:   httpClient,
		baseURL:      strings.TrimRight(baseURL, "/"),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// token fetches a client_credentials access token for the identity service account.
func (c *AdminClient) token(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("identity: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("identity: token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity: token request: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("identity: decode token response: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("identity: token response had no access_token")
	}
	return body.AccessToken, nil
}

// UserEnabled queries Keycloak for kcSub's "enabled" flag (kcSub IS the Keycloak user id — the
// `sub` claim). It NEVER returns KCStateTrue on any failure: token fetch errors, network
// errors, timeouts, non-200 responses (including 404 — an identity DB row whose Keycloak
// account can't be confirmed is exactly the uncertain case this guards against), and malformed
// bodies all collapse to KCStateUnknown. The returned error is for logging only — callers must
// use the state string, never treat a nil error as license to assume enabled.
func (c *AdminClient) UserEnabled(ctx context.Context, kcSub string) (string, error) {
	token, err := c.token(ctx)
	if err != nil {
		return KCStateUnknown, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.realm, url.PathEscape(kcSub))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return KCStateUnknown, fmt.Errorf("identity: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return KCStateUnknown, fmt.Errorf("identity: user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return KCStateUnknown, fmt.Errorf("identity: user request: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return KCStateUnknown, fmt.Errorf("identity: decode user response: %w", err)
	}
	if body.Enabled == nil {
		return KCStateUnknown, fmt.Errorf("identity: user response had no enabled field")
	}
	if *body.Enabled {
		return KCStateTrue, nil
	}
	return KCStateFalse, nil
}

// getUser fetches kcSub's full Keycloak user representation as a raw map — deliberately
// untyped so round-tripping it back through updateUser can't silently drop fields Keycloak
// returned that this package doesn't model.
func (c *AdminClient) getUser(ctx context.Context, kcSub string) (map[string]any, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.realm, url.PathEscape(kcSub))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: build get-user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: get-user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: get-user request: unexpected status %d", resp.StatusCode)
	}

	var user map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("identity: decode get-user response: %w", err)
	}
	return user, nil
}

// updateUser PUTs the full user representation back (Keycloak's user update endpoint expects
// the complete representation, not a patch) — the caller must have obtained it via getUser and
// mutated only what it means to change.
func (c *AdminClient) updateUser(ctx context.Context, kcSub string, user map[string]any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	body, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("identity: marshal user update: %w", err)
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.realm, url.PathEscape(kcSub))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, userURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("identity: build update-user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("identity: update-user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("identity: update-user request: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// SetUserAttribute sets a single Keycloak user attribute (e.g. "kiban_mfa_required") via a
// GET-then-PUT round trip that preserves every other field/attribute Keycloak returned.
func (c *AdminClient) SetUserAttribute(ctx context.Context, kcSub, key, value string) error {
	user, err := c.getUser(ctx, kcSub)
	if err != nil {
		return fmt.Errorf("identity: set user attribute: %w", err)
	}

	attrs, _ := user["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[key] = []string{value}
	user["attributes"] = attrs

	if err := c.updateUser(ctx, kcSub, user); err != nil {
		return fmt.Errorf("identity: set user attribute: %w", err)
	}
	return nil
}
