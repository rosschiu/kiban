// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/store"
)

// The can/batch-can request shape supports an explicit object check: canRequestWire and
// decision.Request carry Object+Relation fields (step 7 of decision.Evaluate,
// internal/authz/decision/evaluate.go — "does the bearer's own subject hold `relation` on
// `Object`", never an arbitrary subject, since the actor is always the bearer per handleCan's
// own actorId-override rejection). A module asking "may THIS caller act as viewer/editor on
// docs_document:<id>" is exactly this request shape with its own object type and relation
// names — no separate endpoint is needed.
//
// The five object-check behaviors are proven here through the REAL
// `/internal/authz/effective-access/can` HTTP endpoint (never a bypass of decision.Evaluate or
// fragment.Check) using a synthetic "test_docs_document" object type standing in for the docs
// module's real fragment.
const testDocsFragment = `{
  "test_docs_document": {
    "company_module": { "this": true },
    "editor": { "this": true },
    "viewer": { "union": [{ "this": true }, { "computedUserset": "editor" }] }
  }
}`

func TestObjectModeCheck_AlreadySupportedByCanEndpoint(t *testing.T) {
	const (
		moduleKey   = "oc-docs-carrier" // the REQUEST's own moduleKey (step 6 gate) — always enabled
		fragMod     = "oc-docs-mod"     // the FRAGMENT's owning module — toggled disabled in the inertness subtest
		companyID   = "oc-docs-co"
		directSub   = "oc-direct-viewer"
		editorSub   = "oc-union-editor"
		missingSub  = "oc-no-tuple"
		inertSub    = "oc-inert-sub"
		docDirect   = "oc-doc-direct"
		docViaUnion = "oc-doc-union"
		docMissing  = "oc-doc-missing"
		docUnknown  = "oc-doc-unknown-type"
		docCap002   = "oc-doc-inert"
	)

	svc, issuer, pool := buildHTTPService(t,
		map[string][]string{directSub: nil, editorSub: nil, missingSub: nil, inertSub: nil},
		map[string]bool{moduleKey: true, fragMod: true},
		map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
		map[string]fakeMembershipFact{
			companyID + "/" + directSub:  {isMember: true, active: true},
			companyID + "/" + editorSub:  {isMember: true, active: true},
			companyID + "/" + missingSub: {isMember: true, active: true},
			companyID + "/" + inertSub:   {isMember: true, active: true},
		},
		false,
	)

	mustExecAuthz(t, pool, `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
	mustExecAuthz(t, pool, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true)`, fragMod, testDocsFragment)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
	})

	mustExecAuthz(t, pool, `DELETE FROM authz.tuple WHERE object_id IN ($1, $2, $3)`, docDirect, docViaUnion, docCap002)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id IN ($1, $2, $3)`, docDirect, docViaUnion, docCap002)
	})

	// docDirect: directSub holds "viewer" directly.
	grantTestDocTuple(t, pool, "test_docs_document", docDirect, "viewer", directSub)
	// docViaUnion: editorSub holds "editor" only — "viewer" must resolve via the union's
	// computedUserset("editor") branch, never a direct tuple.
	grantTestDocTuple(t, pool, "test_docs_document", docViaUnion, "editor", editorSub)
	// docCap002: inertSub holds "viewer" directly too — used to prove the SAME tuple stops
	// answering once its owning module is disabled, not that no tuple exists.
	grantTestDocTuple(t, pool, "test_docs_document", docCap002, "viewer", inertSub)
	// Every object carries its company anchor (the company-binding rule): without it the decision
	// layer denies before the relation is ever evaluated.
	for _, doc := range []string{docDirect, docViaUnion, docCap002} {
		anchorTestDoc(t, pool, doc, companyID, moduleKey)
	}

	canReq := func(t *testing.T, sub, docID, relation string) *httptest.ResponseRecorder {
		t.Helper()
		body := mustJSON(t, map[string]any{
			"featureKey": "docs.document.access", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID,
			"object":    map[string]string{"type": "test_docs_document", "id": docID},
			"relation":  relation,
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, sub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		return rec
	}

	t.Run("allow via direct tuple", func(t *testing.T) {
		rec := canReq(t, directSub, docDirect, "viewer")
		var out struct {
			Data struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		if rec.Code != http.StatusOK || !out.Data.Allowed || out.Data.Reason != "ALLOWED" {
			t.Fatalf("status=%d data=%+v, want 200/allowed/ALLOWED", rec.Code, out.Data)
		}
	})

	t.Run("allow via union rewrite (computedUserset editor->viewer)", func(t *testing.T) {
		rec := canReq(t, editorSub, docViaUnion, "viewer")
		var out struct {
			Data struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		if rec.Code != http.StatusOK || !out.Data.Allowed || out.Data.Reason != "ALLOWED" {
			t.Fatalf("status=%d data=%+v, want 200/allowed/ALLOWED (via union->editor)", rec.Code, out.Data)
		}
	})

	t.Run("deny on missing tuple", func(t *testing.T) {
		rec := canReq(t, missingSub, docMissing, "viewer")
		var out struct {
			Data struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		if rec.Code != http.StatusOK || out.Data.Allowed || out.Data.Reason != "ENGINE_DENIED" {
			t.Fatalf("status=%d data=%+v, want 200/denied/ENGINE_DENIED", rec.Code, out.Data)
		}
	})

	t.Run("deny fail-closed on unknown type (never an allow, never guessed)", func(t *testing.T) {
		// The type below is declared by NO fragment at all: the effective model defines neither
		// `company` nor `company_module` on it, so the company-binding rule denies it before any
		// relation is evaluated (ENGINE_DENIED, objectCompany=false) — a clean, fail-closed
		// deny, never 200 allowed:true.
		body := mustJSON(t, map[string]any{
			"featureKey": "docs.document.access", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID,
			"object":    map[string]string{"type": "test_docs_document_binder_unknown", "id": docUnknown},
			"relation":  "viewer",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer.sign(t, missingSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, req)
		var out struct {
			Data struct {
				Allowed  bool                `json:"allowed"`
				Reason   string              `json:"reason"`
				Evidence []decision.Evidence `json:"evidence"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		if rec.Code != http.StatusOK || out.Data.Allowed || out.Data.Reason != "ENGINE_DENIED" {
			t.Fatalf("status=%d data=%+v, want 200/denied/ENGINE_DENIED (unbindable type)", rec.Code, out.Data)
		}
		if v, _ := evidenceValue(out.Data.Evidence, "objectCompany"); v != "false" {
			t.Fatalf("objectCompany evidence = %q, want false", v)
		}
	})

	t.Run("disabled-module inertness: a REAL tuple still answers false, never an error, never allow", func(t *testing.T) {
		// Re-register the identical company/module/registry wiring but with fragMod DISABLED —
		// a fresh Service so KnownEnabled reflects the new registry snapshot.
		svc2, issuer2, pool2 := buildHTTPService(t,
			map[string][]string{inertSub: nil},
			map[string]bool{moduleKey: true, fragMod: false}, // fragMod known but DISABLED
			map[string]fakeCompanyFact{companyID: {exists: true, active: true}},
			map[string]fakeMembershipFact{companyID + "/" + inertSub: {isMember: true, active: true}},
			false,
		)
		mustExecAuthz(t, pool2, `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
		mustExecAuthz(t, pool2, `INSERT INTO authz.model_fragment (module_key, fragment, active) VALUES ($1, $2::jsonb, true)`, fragMod, testDocsFragment)
		t.Cleanup(func() {
			_, _ = pool2.Exec(context.Background(), `DELETE FROM authz.model_fragment WHERE module_key = $1`, fragMod)
		})
		mustExecAuthz(t, pool2, `DELETE FROM authz.tuple WHERE object_id = $1`, docCap002)
		grantTestDocTuple(t, pool2, "test_docs_document", docCap002, "viewer", inertSub)
		anchorTestDoc(t, pool2, docCap002, companyID, moduleKey)
		t.Cleanup(func() {
			_, _ = pool2.Exec(context.Background(), `DELETE FROM authz.tuple WHERE object_id = $1`, docCap002)
		})

		body := mustJSON(t, map[string]any{
			"featureKey": "docs.document.access", "moduleKey": moduleKey, "scope": "company",
			"companyId": companyID,
			"object":    map[string]string{"type": "test_docs_document", "id": docCap002},
			"relation":  "viewer",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/authz/effective-access/can", body)
		req.Header.Set("Authorization", "Bearer "+issuer2.sign(t, inertSub, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		svc2.Routes().ServeHTTP(rec, req)

		var out struct {
			Data struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"data"`
		}
		decodeBody(t, rec, &out)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (disabled-module inertness is a clean deny, never an error/503), body=%s", rec.Code, rec.Body.String())
		}
		if out.Data.Allowed {
			t.Fatalf("disabled-module inertness: a real tuple under a DISABLED module's type must never allow, got allowed=true")
		}
		if out.Data.Reason != "ENGINE_DENIED" {
			t.Fatalf("reason = %q, want ENGINE_DENIED (inert, not an error reason)", out.Data.Reason)
		}
	})
}

// grantTestDocTuple grants one tuple through the real transactional store.Grant (never a raw
// INSERT), the same production write path modules use.
func grantTestDocTuple(t *testing.T, pool *pgxpool.Pool, objType, objID, relation, subjectID string) {
	t.Helper()
	grantTestTuple(t, pool, store.Tuple{ObjectType: objType, ObjectID: objID, Relation: relation, SubjectType: "user", SubjectID: subjectID})
}

// anchorTestDoc writes the document's company anchor — the tuple modulekit.AnchorTuple shapes
// and every module grants on object create: `test_docs_document:<doc>#company_module @
// company_module:<companyID>/<moduleKey>`.
func anchorTestDoc(t *testing.T, pool *pgxpool.Pool, docID, companyID, moduleKey string) {
	t.Helper()
	grantTestTuple(t, pool, store.Tuple{
		ObjectType: "test_docs_document", ObjectID: docID, Relation: "company_module",
		SubjectType: "company_module", SubjectID: companyID + "/" + moduleKey,
	})
}

func grantTestTuple(t *testing.T, pool *pgxpool.Pool, tp store.Tuple) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.Grant(ctx, tx, "test-fixture", "", tp); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
