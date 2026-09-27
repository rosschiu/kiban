// SPDX-License-Identifier: Apache-2.0

//go:build live

package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// A service client reconciled by RealmStep's step 3c yields, through the client-credentials
// grant, a token the gateway accepts: same audience, same issuer, a real subject the gateway
// provisions like any user. The proof is a 200 from an /api route (an empty company list: the
// service account is a member of nothing until an administrator adds it).
func TestLive_ServiceClient_TokenPassesGateway(t *testing.T) {
	deps := realmTestDeps(t)
	ctx := context.Background()
	kc := newKCMasterClient(deps.HTTPClient, deps.KeycloakAdminBaseURL, deps.KeycloakRealm, deps.KCBootstrapAdminUsername, deps.KCBootstrapAdminPassword)
	const clientID = "kiban-live-test-service"

	_, internalID, err := reconcileServiceClient(ctx, kc, clientID)
	if err != nil {
		t.Fatalf("reconcileServiceClient: %v", err)
	}
	t.Cleanup(func() { _, _ = kc.do(context.Background(), http.MethodDelete, "/clients/"+internalID, nil, nil) })
	if _, err := reconcileAudienceMapper(ctx, kc, internalID); err != nil {
		t.Fatalf("reconcileAudienceMapper: %v", err)
	}
	if changed, _, err := reconcileServiceClient(ctx, kc, clientID); err != nil || changed {
		t.Fatalf("second reconcile: changed=%v err=%v, want converged", changed, err)
	}
	secret, err := kc.clientSecret(ctx, internalID)
	if err != nil {
		t.Fatalf("clientSecret: %v", err)
	}

	gwBase := "https://127.0.0.1:" + bootstrapTestEnvOrDefault("KIBAN_GATEWAY_TLS_HOST_PORT", "8443")
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // self-signed dev cert
	}
	tokenResp, err := client.PostForm(fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", gwBase, deps.KeycloakRealm), url.Values{
		"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret},
	})
	if err != nil {
		t.Fatalf("POST token endpoint: %v", err)
	}
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint = HTTP %d: %s", tokenResp.StatusCode, tokenBody)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenBody, &tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("decode token response: %v (%s)", err, tokenBody)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gwBase+"/api/org/me/companies", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/org/me/companies: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/org/me/companies with a service token = HTTP %d: %s", resp.StatusCode, body)
	}
}
