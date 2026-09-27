// SPDX-License-Identifier: Apache-2.0

//go:build harness

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a minimal OpenFGA REST client — only the four calls the harness needs
// (create store, write authorization model, write tuples, check). Not a general SDK; OpenFGA
// itself is never a Go dependency (Forbidden) — this just speaks its plain HTTP API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, string(respBody))
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w (body=%s)", method, path, err, string(respBody))
		}
	}
	return nil
}

func (c *Client) CreateStore(ctx context.Context, name string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/stores", map[string]string{"name": name}, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (c *Client) WriteAuthorizationModel(ctx context.Context, storeID string, model fgaModel) (string, error) {
	var out struct {
		AuthorizationModelID string `json:"authorization_model_id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/stores/"+storeID+"/authorization-models", model, &out); err != nil {
		return "", err
	}
	return out.AuthorizationModelID, nil
}

// TupleKey is one OpenFGA tuple (user/relation/object), "user" already formatted as
// "type:id" or "type:id#relation" for a userset subject.
type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// WriteTuples writes tuples in batches (OpenFGA's default MaxTuplesPerWrite is 100).
func (c *Client) WriteTuples(ctx context.Context, storeID string, tuples []TupleKey) error {
	const batchSize = 100
	for i := 0; i < len(tuples); i += batchSize {
		end := i + batchSize
		if end > len(tuples) {
			end = len(tuples)
		}
		body := map[string]any{
			"writes": map[string]any{"tuple_keys": tuples[i:end]},
		}
		if err := c.doJSON(ctx, http.MethodPost, "/stores/"+storeID+"/write", body, nil); err != nil {
			return fmt.Errorf("write batch [%d:%d]: %w", i, end, err)
		}
	}
	return nil
}

// WriteTupleSingle writes exactly one tuple, returning the raw error (unwrapped) so callers can
// detect a per-tuple type-restriction rejection without losing the rest of a batch.
func (c *Client) WriteTupleSingle(ctx context.Context, storeID string, t TupleKey) error {
	body := map[string]any{"writes": map[string]any{"tuple_keys": []TupleKey{t}}}
	return c.doJSON(ctx, http.MethodPost, "/stores/"+storeID+"/write", body, nil)
}

// DeleteTupleSingle deletes exactly one tuple (the revoke leg of the position mutation test:
// grant -> check -> revoke -> re-grant to a different subject -> check both).
func (c *Client) DeleteTupleSingle(ctx context.Context, storeID string, t TupleKey) error {
	body := map[string]any{"deletes": map[string]any{"tuple_keys": []TupleKey{t}}}
	return c.doJSON(ctx, http.MethodPost, "/stores/"+storeID+"/write", body, nil)
}

func (c *Client) Check(ctx context.Context, storeID, modelID string, t TupleKey) (bool, error) {
	body := map[string]any{
		"tuple_key":              t,
		"authorization_model_id": modelID,
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/stores/"+storeID+"/check", body, &out); err != nil {
		return false, err
	}
	return out.Allowed, nil
}

func (c *Client) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
