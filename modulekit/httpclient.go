// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// postJSON is the one S2S POST every client method shares: marshal in, forward the acting
// user's bearer verbatim, require 200, decode into out when out is non-nil. what names the
// call in error strings ("<prefix>: build <what> request: ...").
func postJSON(ctx context.Context, client *http.Client, prefix, u, rawBearer, what string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("%s: marshal %s request: %w", prefix, what, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("%s: build %s request: %w", prefix, what, err)
	}
	req.Header.Set("Authorization", rawBearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s request: %w", prefix, what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s request: HTTP %d", prefix, what, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s: decode %s response: %w", prefix, what, err)
	}
	return nil
}

// getJSON is the one S2S GET the org facts reads share (no bearer: org's internal facts API is
// unauthenticated at that layer). A 404 returns notFound when it is non-nil; any other non-200
// is "<prefix>: <what>: HTTP <code>".
func getJSON(ctx context.Context, client *http.Client, prefix, u, what string, out any, notFound error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("%s: build %s request: %w", prefix, what, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s request: %w", prefix, what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && notFound != nil {
		return notFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s: HTTP %d", prefix, what, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s: decode %s response: %w", prefix, what, err)
	}
	return nil
}
