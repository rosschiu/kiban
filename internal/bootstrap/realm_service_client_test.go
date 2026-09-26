// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestReconcileServiceClient(t *testing.T) {
	t.Run("missing: created confidential with a service account and no interactive flow", func(t *testing.T) {
		var created kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{})
			case http.MethodPost:
				_ = json.NewDecoder(r.Body).Decode(&created)
				w.Header().Set("Location", "http://kc/admin/realms/kiban/clients/sc-id")
				w.WriteHeader(http.StatusCreated)
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
			}
		})
		changed, id, err := reconcileServiceClient(context.Background(), kc, "tokidesk-worker")
		if err != nil {
			t.Fatalf("reconcileServiceClient: %v", err)
		}
		if !changed || id != "sc-id" || created.ClientID != "tokidesk-worker" || created.PublicClient ||
			!created.ServiceAccountsEnabled || created.StandardFlowEnabled || created.DirectAccessGrantsEnabled || !created.Enabled {
			t.Errorf("changed=%v id=%q created=%+v", changed, id, created)
		}
	})

	t.Run("present and correct: converged", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, []kcClientRep{{ID: "sc-id", ClientID: "tokidesk-worker", Enabled: true, ServiceAccountsEnabled: true}})
		})
		changed, id, err := reconcileServiceClient(context.Background(), kc, "tokidesk-worker")
		if err != nil || changed || id != "sc-id" {
			t.Errorf("changed=%v id=%q err=%v, want converged", changed, id, err)
		}
	})

	t.Run("present but public with a browser flow: repaired", func(t *testing.T) {
		var updated kcClientRep
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, []kcClientRep{{ID: "sc-id", ClientID: "tokidesk-worker", Enabled: true, PublicClient: true, StandardFlowEnabled: true}})
			case http.MethodPut:
				_ = json.NewDecoder(r.Body).Decode(&updated)
				w.WriteHeader(http.StatusNoContent)
			}
		})
		changed, _, err := reconcileServiceClient(context.Background(), kc, "tokidesk-worker")
		if err != nil || !changed || updated.PublicClient || updated.StandardFlowEnabled || !updated.ServiceAccountsEnabled {
			t.Errorf("changed=%v updated=%+v err=%v, want repaired", changed, updated, err)
		}
	})

	t.Run("lookup error propagates", func(t *testing.T) {
		kc := fakeKCFor(t, "kiban", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		if _, _, err := reconcileServiceClient(context.Background(), kc, "x"); err == nil {
			t.Fatal("expected an error")
		}
	})
}
