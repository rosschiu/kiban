// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz/decision"
	"github.com/rosschiu/kiban/internal/authz/engine"
	"github.com/rosschiu/kiban/internal/authz/fragment"
	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// Service wires the engine, fragment loader, store and decision behind the HTTP surface.
// DebugCheck, when true, exposes the raw diagnostics-only `check` endpoint.
type Service struct {
	Pool         *pgxpool.Pool
	Audit        *audit.Writer
	KnownEnabled func(ctx context.Context) (map[string]bool, error) // registry-known+enabled module keys, for fragment.Load
	Verifier     *TokenVerifier
	DebugCheck   bool

	Identity *IdentityClient
	Registry *RegistryClient
	Org      *OrgClient

	// Metrics records kiban_authz_decisions_total{reason} + kiban_authz_decision_duration_seconds
	// for the two real enforcement endpoints (/effective-access/can, /batch-can) —
	// deliberately NOT the /effective-access/summary endpoint's own internal decider.Evaluate
	// calls (summary.go), which compose a display read across every feature/module rather than
	// answer one real enforcement question; counting those under the same metric would make
	// "DENY reason spiking" alerts fire on ordinary nav-summary reads instead of real access
	// checks. A nil Metrics (e.g. tests that don't wire it) makes recordDecision/
	// recordBatchDecisions no-ops via *metrics.Registry's own nil-receiver safety.
	Metrics *metrics.Registry
}

// evaluate runs decider.Evaluate and records the outcome via svc.Metrics — the
// single call site handleCan uses, so the real /can enforcement decision is always measured.
func (svc *Service) evaluate(ctx context.Context, decider *decision.Decider, req decision.Request) decision.Decision {
	start := time.Now()
	d := decider.Evaluate(ctx, req)
	svc.Metrics.RecordAuthzDecision(string(d.Reason), time.Since(start))
	return d
}

// evaluateBatch runs decider.EvaluateBatch and records each item's own outcome individually —
// batch-can is still N real enforcement decisions, one per item, not one.
func (svc *Service) evaluateBatch(ctx context.Context, decider *decision.Decider, base decision.Request, items []decision.BatchItem) []decision.BatchResult {
	start := time.Now()
	results := decider.EvaluateBatch(ctx, base, items)
	elapsed := time.Since(start)
	perItem := elapsed
	if n := len(results); n > 0 {
		perItem = elapsed / time.Duration(n)
	}
	for _, res := range results {
		svc.Metrics.RecordAuthzDecision(string(res.Decision.Reason), perItem)
	}
	return results
}

func (svc *Service) subjectSource() decision.SubjectSource         { return svc.Identity }
func (svc *Service) keycloakSource() decision.KeycloakSource       { return svc.Identity }
func (svc *Service) moduleStateSource() decision.ModuleStateSource { return svc.Registry }

// companySource / membershipSource implement decision.CompanySource/MembershipSource (step 5):
// rides org's real company-facts endpoints via OrgClient.
func (svc *Service) companySource() decision.CompanySource       { return svc.Org }
func (svc *Service) membershipSource() decision.MembershipSource { return svc.Org }

// effectiveEngine builds the current fragment-loaded model and returns a fragment-aware
// checker (unknown or disabled modules' object types answer false, never an error).
func (svc *Service) effectiveEngine(ctx context.Context) (*engine.Engine, fragment.Loaded, error) {
	known, err := svc.KnownEnabled(ctx)
	if err != nil {
		return nil, fragment.Loaded{}, err
	}
	loaded, err := fragment.Load(ctx, svc.Pool, known)
	if err != nil {
		return nil, fragment.Loaded{}, err
	}
	return &engine.Engine{Pool: svc.Pool, Model: loaded.Model}, loaded, nil
}
