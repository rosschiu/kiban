// SPDX-License-Identifier: Apache-2.0

//go:build live

// Live-tagged proofs, run against the isolated kiban-test stack's REAL Postgres
// (org/authz/notification's own runtime DB roles) with REAL, wired production service
// instances (org.Service, authz decision via THIS package's own Service, and
// notification.Service+Store — never fakes standing in for another platform service; mocks
// only for genuinely external systems like Keycloak, which this file doesn't need).
// Run with `go test -tags live ./internal/authz/ -run TestLive_ -v`.
package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/audit"
	notification "github.com/rosschiu/kiban/modules/notification/service"

	"github.com/rosschiu/kiban/internal/livestack"
	"github.com/rosschiu/kiban/internal/org"
)

// --- Live proof: member directory 200 for a member, 403 for a non-member. ---

func TestLive_MemberDirectory_MemberAllowedNonMemberDenied(t *testing.T) {
	orgStore := org.NewStore(orgTestPool(t), mustAuditWriter(t, "audit.org__events"))
	orgSvc := org.NewService(orgStore, noopIdentityChecker{}, org.NewDenyAllAuthorizer(), mustAuditWriter(t, "audit.org__events"))
	orgSrv := httptest.NewServer(orgSvc.Routes())
	t.Cleanup(orgSrv.Close)

	admin := adminPool(t)
	companyID := seedCompanyAndMember(t, &realOrgFixture{store: orgStore, orgURL: orgSrv.URL}, admin, "LIVEMDIR", "LIVEM1", "live-member")

	t.Run("active member: 200", func(t *testing.T) {
		resp, err := http.Get(orgSrv.URL + "/internal/org/companies/" + companyID.String() + "/members?kcSub=live-member")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("non-member: 403", func(t *testing.T) {
		resp, err := http.Get(orgSrv.URL + "/internal/org/companies/" + companyID.String() + "/members?kcSub=live-stranger")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
}

// --- Live proof: object-check allow + deny through the real can endpoint. ---

func TestLive_ObjectCheck_AllowAndDeny(t *testing.T) {
	const (
		moduleKey = "live-carrier"
		fragMod   = "live-docs-mod"
		companyID = "live-docs-co"
		allowSub  = "live-allow-sub"
		denySub   = "live-deny-sub"
		docAllow  = "live-doc-allow"
		docDeny   = "live-doc-deny"
	)
	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{allowSub: nil, denySub: nil},
		map[string]bool{moduleKey: true, fragMod: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyID + "/" + allowSub: {isMember: true, active: true},
			companyID + "/" + denySub:  {isMember: true, active: true},
		},
		false,
	)
	mustExecAuthz(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
	mustExecAuthz(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true)`, fragMod, testDocsFragment)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
	})
	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id = $1`, docAllow)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, docAllow)
	})
	grantTestDocTuple(t, pool, "test_docs_document", docAllow, "viewer", allowSub)
	anchorTestDoc(t, pool, docAllow, companyID, moduleKey)

	can := func(sub, docID string) (allowed bool, reason string) {
		body := mustJSON(t, map[string]any{
			"featureKey": "docs.document.access", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID, "object": map[string]string{"type": "test_docs_document", "id": docID}, "relation": "viewer",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, sub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		var out struct {
			Data struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Data.Allowed, out.Data.Reason
	}

	if allowed, reason := can(allowSub, docAllow); !allowed || reason != "ALLOWED" {
		t.Fatalf("expected allow: allowed=%v reason=%s", allowed, reason)
	}
	if allowed, reason := can(denySub, docDeny); allowed || reason != "ENGINE_DENIED" {
		t.Fatalf("expected deny: allowed=%v reason=%s", allowed, reason)
	}
}

// --- Live proof: cross-module event lands in the recipient's inbox, not a non-recipient's. ---

func TestLive_TargetedEvent_RecipientOnly(t *testing.T) {
	pool := livestack.Pool(t, "kiban_notification", testEnv(t, "KIBAN_NOTIFICATION_DB_PASSWORD"))
	notifAuditWriter := mustAuditWriter(t, "audit.notification__events")
	notifStore := notification.NewStore(pool, notifAuditWriter, "live-"+time.Now().Format("150405"), notification.NewWebhookPolicyFromEnv())

	orgStore := org.NewStore(orgTestPool(t), mustAuditWriter(t, "audit.org__events"))
	orgSvc := org.NewService(orgStore, noopIdentityChecker{}, org.NewDenyAllAuthorizer(), mustAuditWriter(t, "audit.org__events"))
	orgSrv := httptest.NewServer(orgSvc.Routes())
	t.Cleanup(orgSrv.Close)
	orgClient := notification.NewOrgClient(orgSrv.Client(), orgSrv.URL)

	admin := adminPool(t)
	companyID := seedCompanyAndMember(t, &realOrgFixture{store: orgStore, orgURL: orgSrv.URL}, admin, "LIVEEVCO", "LIVEEVM1", "live-recipient")

	ctx := context.Background()
	sent, skipped, err := notifStore.SendTargetedEvent(ctx, orgClient, "live-actor", companyID,
		"docs", "A document was shared with you", "Live proof body", []string{"live-recipient", "live-not-a-member"})
	if err != nil {
		t.Fatalf("SendTargetedEvent: %v", err)
	}
	if sent != 1 || skipped != 1 {
		t.Fatalf("sent=%d skipped=%d, want sent=1 skipped=1", sent, skipped)
	}

	recipientInbox, total, err := notifStore.ListInbox(ctx, companyID, "live-recipient", 1, 25)
	if err != nil {
		t.Fatalf("ListInbox (recipient): %v", err)
	}
	if total != 1 || len(recipientInbox) != 1 || recipientInbox[0].SubjectLine != "A document was shared with you" {
		t.Fatalf("recipient inbox = %+v (total=%d), want exactly the targeted event", recipientInbox, total)
	}

	nonRecipientInbox, nonTotal, err := notifStore.ListInbox(ctx, companyID, "live-not-a-member", 1, 25)
	if err != nil {
		t.Fatalf("ListInbox (non-recipient): %v", err)
	}
	if nonTotal != 0 || len(nonRecipientInbox) != 0 {
		t.Fatalf("non-recipient inbox = %+v (total=%d), want empty (they were never a member, must be skipped)", nonRecipientInbox, nonTotal)
	}
}

func mustAuditWriter(t *testing.T, table string) *audit.Writer {
	t.Helper()
	w, err := audit.NewWriter(table)
	if err != nil {
		t.Fatalf("build audit writer for %s: %v", table, err)
	}
	return w
}
