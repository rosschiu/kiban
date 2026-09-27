// SPDX-License-Identifier: Apache-2.0

// Package sdk is the Go client for an application that runs beside Kiban: the app's backend
// authenticates as its registered service client, verifies the user tokens Kiban's login
// issued, asks for access decisions, writes and removes relation tuples on the app's own
// object types, and looks members up — all through the gateway's public API, never by
// network position.
//
//	client, err := sdk.New(ctx, sdk.Config{GatewayURL: "https://kiban.example", ClientID: "tokidesk-backend", ClientSecret: secret})
//	sub, err := client.VerifyUserToken(ctx, bearer)            // the user behind a request
//	d, err := client.Can(ctx, bearer, sdk.CanRequest{...})       // may this user do this here?
//	err = client.Grant(ctx, companyID, sdk.Tuple{...})           // the app owns its own types
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rosschiu/kiban/modulekit"
)

// Config names the Kiban deployment and the app's service client (KIBAN_SERVICE_CLIENTS).
type Config struct {
	// GatewayURL is the gateway's origin, e.g. "https://kiban.example". Login, JWKS and the
	// API all hang off it.
	GatewayURL string
	// Realm defaults to "kiban".
	Realm string
	// ClientID and ClientSecret are the app's confidential service client.
	ClientID     string
	ClientSecret string
	// Audience defaults to "kiban-api".
	Audience string
	// HTTPClient defaults to one with a 15 s timeout.
	HTTPClient *http.Client
}

// Client is safe for concurrent use.
type Client struct {
	cfg      Config
	http     *http.Client
	verifier *modulekit.TokenVerifier

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// Tuple is one relation tuple: object#relation@subject (subjectRelation for a userset).
type Tuple = modulekit.Tuple

// CanRequest asks "may the bearer use featureKey of moduleKey in companyId?", optionally
// bound to one object relation.
type CanRequest struct {
	FeatureKey string `json:"featureKey"`
	ModuleKey  string `json:"moduleKey,omitempty"`
	CompanyID  string `json:"companyId,omitempty"`
	Scope      string `json:"scope,omitempty"` // "company" (default) or "global"
	Object     *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"object,omitempty"`
	Relation string `json:"relation,omitempty"`
}

// Decision is Kiban's answer: allowed, or denied with one of the frozen reason codes.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// MemberFact answers "is this subject an active member of this company, and which member".
type MemberFact struct {
	IsMember bool    `json:"isMember"`
	IsActive bool    `json:"isActive"`
	MemberID *string `json:"memberId"`
}

// AppManifest registers the app: its key, service client, feature keys and object types.
type AppManifest struct {
	Key             string          `json:"key"`
	DisplayName     string          `json:"displayName"`
	Version         string          `json:"version"`
	ServiceClientID string          `json:"serviceClientId"`
	Features        []string        `json:"features,omitempty"`
	AuthzFragment   json.RawMessage `json:"authzFragment"`
}

// APIError is Kiban's error envelope.
type APIError struct {
	Status  int
	Code    string
	Message string
	Details any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kiban: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// ErrTokenInvalid is returned by VerifyUserToken for a token Kiban did not issue, or one that
// expired or names another audience.
var ErrTokenInvalid = modulekit.ErrTokenInvalid

// New validates cfg and fetches the realm's signing keys once; a gateway that cannot be
// reached is an error here, not later.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.GatewayURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("kiban sdk: GatewayURL, ClientID and ClientSecret are required")
	}
	cfg.GatewayURL = strings.TrimRight(cfg.GatewayURL, "/")
	if cfg.Realm == "" {
		cfg.Realm = "kiban"
	}
	if cfg.Audience == "" {
		cfg.Audience = "kiban-api"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	issuer := cfg.GatewayURL + "/realms/" + cfg.Realm
	v, err := modulekit.NewTokenVerifierHTTP(ctx, cfg.HTTPClient, issuer+"/protocol/openid-connect/certs", issuer, cfg.Audience, "kiban sdk")
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, http: cfg.HTTPClient, verifier: v}, nil
}

// VerifyUserToken checks a bearer a user presented to the app and returns its subject.
func (c *Client) VerifyUserToken(ctx context.Context, bearer string) (string, error) {
	return c.verifier.Verify(ctx, bearer)
}

// ServiceToken returns the app's own access token (client credentials), refreshed before it
// expires. Callers rarely need it directly; the methods below use it.
func (c *Client) ServiceToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiresAt) > 30*time.Second {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.GatewayURL+"/realms/"+c.cfg.Realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("kiban sdk: token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kiban sdk: token: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("kiban sdk: token: bad response")
	}
	c.token, c.expiresAt = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return c.token, nil
}

// Can asks for a decision on behalf of the user whose bearer the app received. Kiban answers
// for that bearer only.
func (c *Client) Can(ctx context.Context, userBearer string, req CanRequest) (Decision, error) {
	var d Decision
	err := c.do(ctx, userBearer, http.MethodPost, "/api/auth/effective-access/can", req, &d)
	return d, err
}

// CanService asks for a decision for the app's own service account (a background job).
func (c *Client) CanService(ctx context.Context, req CanRequest) (Decision, error) {
	tok, err := c.ServiceToken(ctx)
	if err != nil {
		return Decision{}, err
	}
	return c.Can(ctx, tok, req)
}

// Grant writes tuples on the app's own object types in companyID. Every module object must
// carry its company anchor; AnchorTuple builds it.
func (c *Client) Grant(ctx context.Context, companyID string, tuples ...Tuple) error {
	return c.grants(ctx, "grant", companyID, tuples)
}

// Revoke removes tuples the app wrote.
func (c *Client) Revoke(ctx context.Context, companyID string, tuples ...Tuple) error {
	return c.grants(ctx, "revoke", companyID, tuples)
}

// AnchorTuple is the `<objectType>:<objectID>#company_module @ company_module:<companyID>/<appKey>`
// tuple every object of the app must carry: it binds the object to the company. Write it in the
// same Grant call as the object's first tuple.
func AnchorTuple(appKey, objectType, objectID, companyID string) Tuple {
	return Tuple{ObjectType: objectType, ObjectID: objectID, Relation: "company_module", SubjectType: "company_module", SubjectID: companyID + "/" + appKey}
}

func (c *Client) grants(ctx context.Context, op, companyID string, tuples []Tuple) error {
	tok, err := c.ServiceToken(ctx)
	if err != nil {
		return err
	}
	body := map[string]any{"op": op, "companyId": companyID, "tuples": tuples}
	return c.do(ctx, tok, http.MethodPost, "/api/auth/grants", body, nil)
}

// MemberBySubject asks org whether subject is an active member of companyID.
func (c *Client) MemberBySubject(ctx context.Context, companyID, subject string) (MemberFact, error) {
	tok, err := c.ServiceToken(ctx)
	if err != nil {
		return MemberFact{}, err
	}
	var f MemberFact
	err = c.do(ctx, tok, http.MethodGet, "/api/org/companies/"+url.PathEscape(companyID)+"/members/by-subject/"+url.PathEscape(subject), nil, &f)
	return f, err
}

// RegisterApp registers (or re-registers) the app with a superadmin's bearer. Typically run
// once by an operator or at the app's first start.
func (c *Client) RegisterApp(ctx context.Context, superadminBearer string, m AppManifest) error {
	return c.do(ctx, superadminBearer, http.MethodPost, "/api/platform/admin/apps", m, nil)
}

func (c *Client) do(ctx context.Context, bearer, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.GatewayURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kiban sdk: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details any    `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode >= 400 {
		e := &APIError{Status: resp.StatusCode, Code: "HTTP_" + fmt.Sprint(resp.StatusCode), Message: strings.TrimSpace(string(raw))}
		if env.Error != nil {
			e.Code, e.Message, e.Details = env.Error.Code, env.Error.Message, env.Error.Details
		}
		return e
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
