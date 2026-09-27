// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// IdentityClient calls identity's HTTP API to confirm a kcSub resolves to a real account before
// org links a member to it — validated over HTTP, never by trusting input. It implements
// Store.IdentityStateChecker.
type IdentityClient struct {
	httpClient *http.Client
	baseURL    string // e.g. "http://127.0.0.1:8120" — no trailing slash
}

// NewIdentityClient builds an IdentityClient. httpClient's Timeout governs the call — a
// slow/unreachable identity service must fail fast into "not confirmed" rather than hang the
// caller (same fail-closed shape as identity's own AdminClient.UserEnabled).
func NewIdentityClient(httpClient *http.Client, baseURL string) *IdentityClient {
	return &IdentityClient{httpClient: httpClient, baseURL: strings.TrimRight(baseURL, "/")}
}

// UserExists calls GET /internal/identity/users/{kcSub}/state and reports whether identity
// confirmed the account exists. A 404 returns (false, nil): identity answered that the account
// does not exist. Any other non-200 status or a transport/decode error returns (false, non-nil).
// Neither outcome is ever reported as "exists".
func (c *IdentityClient) UserExists(ctx context.Context, kcSub string) (bool, error) {
	stateURL := fmt.Sprintf("%s/internal/identity/users/%s/state", c.baseURL, url.PathEscape(kcSub))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stateURL, nil)
	if err != nil {
		return false, fmt.Errorf("org: build identity state request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("org: identity state request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("org: identity state request: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Lifecycle string `json:"lifecycle"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("org: decode identity state response: %w", err)
	}
	return body.Data.Lifecycle != "", nil
}
