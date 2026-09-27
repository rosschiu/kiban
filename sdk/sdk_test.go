// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rosschiu/kiban/modulekit/kittest"
)

// A fake gateway: JWKS and token endpoint under /realms/kiban, and the four public routes the
// SDK uses. Every API route records the bearer it saw.
func fakeGateway(t *testing.T, iss *kittest.Issuer) (*httptest.Server, *atomic.Int32, *[]map[string]any, *[]string) {
	t.Helper()
	var tokenCalls atomic.Int32
	var grants []map[string]any
	var bearers []string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("GET /realms/kiban/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(iss.JWKS.URL)
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, resp.Body)
	})
	mux.HandleFunc("POST /realms/kiban/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "app-backend" || r.Form.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tok := iss.Sign(t, srv.URL+"/realms/kiban", "kiban-api", "service-account-app-backend", time.Now().Add(5*time.Minute))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": 300})
	})
	record := func(r *http.Request) {
		bearers = append(bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	mux.HandleFunc("POST /api/auth/effective-access/can", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := req["featureKey"] == "app.ticket.view"
		reason := "ALLOWED"
		if !allowed {
			reason = "ENGINE_DENIED"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": allowed, "reason": reason}})
	})
	mux.HandleFunc("POST /api/auth/grants", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		grants = append(grants, body)
		if body["companyId"] == "other" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "AUTHORIZATION_DENIED", "message": "not yours"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "ok"}})
	})
	mux.HandleFunc("GET /api/org/companies/{companyId}/members/by-subject/{subject}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": true, "memberId": "m-1"}})
	})
	mux.HandleFunc("POST /api/platform/admin/apps", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"module": "app"}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &tokenCalls, &grants, &bearers
}

func TestClient(t *testing.T) {
	iss := kittest.NewIssuer(t)
	gw, tokenCalls, grants, bearers := fakeGateway(t, iss)
	ctx := context.Background()

	if _, err := New(ctx, Config{GatewayURL: gw.URL}); err == nil {
		t.Fatal("New without a client id must fail")
	}
	c, err := New(ctx, Config{GatewayURL: gw.URL + "/", ClientID: "app-backend", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	userTok := iss.Sign(t, gw.URL+"/realms/kiban", "kiban-api", "alice", time.Now().Add(time.Hour))
	if sub, err := c.VerifyUserToken(ctx, userTok); err != nil || sub != "alice" {
		t.Fatalf("VerifyUserToken = %q, %v", sub, err)
	}
	wrongAud := iss.Sign(t, gw.URL+"/realms/kiban", "other-api", "alice", time.Now().Add(time.Hour))
	if _, err := c.VerifyUserToken(ctx, wrongAud); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong audience: err = %v, want ErrTokenInvalid", err)
	}

	d, err := c.Can(ctx, userTok, CanRequest{FeatureKey: "app.ticket.view", ModuleKey: "app", CompanyID: "co-1"})
	if err != nil || !d.Allowed {
		t.Fatalf("Can = %+v, %v", d, err)
	}
	if (*bearers)[0] != userTok {
		t.Fatal("Can must send the user's own bearer")
	}

	if err := c.Grant(ctx, "co-1", AnchorTuple("app", "ticket", "t-1", "co-1"), Tuple{ObjectType: "ticket", ObjectID: "t-1", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := c.Revoke(ctx, "co-1", Tuple{ObjectType: "ticket", ObjectID: "t-1", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(*grants) != 2 || (*grants)[0]["op"] != "grant" || (*grants)[1]["op"] != "revoke" || (*grants)[0]["companyId"] != "co-1" {
		t.Fatalf("grants = %v", *grants)
	}
	if tuples := (*grants)[0]["tuples"].([]any); len(tuples) != 2 || tuples[0].(map[string]any)["subjectId"] != "co-1/app" {
		t.Fatalf("anchor tuple missing: %v", tuples)
	}
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (cached)", got)
	}
	if sub, err := c.VerifyUserToken(ctx, (*bearers)[1]); err != nil || sub != "service-account-app-backend" {
		t.Fatalf("grants must carry the service token: sub=%q err=%v", sub, err)
	}

	var apiErr *APIError
	if err := c.Grant(ctx, "other", Tuple{}); !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != "AUTHORIZATION_DENIED" {
		t.Fatalf("denied grant: err = %v", err)
	}

	f, err := c.MemberBySubject(ctx, "co-1", "alice")
	if err != nil || !f.IsMember || f.MemberID == nil || *f.MemberID != "m-1" {
		t.Fatalf("MemberBySubject = %+v, %v", f, err)
	}
	if err := c.RegisterApp(ctx, "superadmin-token", AppManifest{Key: "app", DisplayName: "App", Version: "1", ServiceClientID: "app-backend", AuthzFragment: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("RegisterApp: %v", err)
	}
	if last := (*bearers)[len(*bearers)-1]; last != "superadmin-token" {
		t.Fatalf("RegisterApp must send the superadmin bearer, sent %q", last)
	}
	if d, err := c.CanService(ctx, CanRequest{FeatureKey: "app.nope"}); err != nil || d.Allowed || d.Reason != "ENGINE_DENIED" {
		t.Fatalf("CanService = %+v, %v", d, err)
	}
}
