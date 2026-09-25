// SPDX-License-Identifier: Apache-2.0

// Command authz runs kiban-authz: the authz service (subset-walled fragment-loaded engine,
// transactional grant API, the layered fail-closed effective-access decision). It connects to
// Postgres as its own DB role, kiban_authz — migrations run separately, as the kiban owner,
// via `make migrate-authz`.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/authz"
	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/version"
)

// dbUser is the runtime role migrations/authz creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_authz"

// listenPort is fixed; the host part is configurable via KIBAN_LISTEN_ADDR: defaults to
// 127.0.0.1 for a host-run process; compose sets 0.0.0.0 INSIDE this service's own container
// (infra/compose.yaml). No port beyond the gateway's own is published to the HOST (the
// gateway is the edge).
const listenPort = "8140"

const jwksRefreshInterval = 10 * time.Minute

func main() {
	logger := obs.New("authz")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("authz: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-authz end to end (config -> DB -> Keycloak verifier -> downstream clients ->
// service -> HTTP listener), shutting down gracefully when ctx is cancelled. ctx is a parameter
// (not created here) so tests can drive startup/shutdown deterministically without relying on OS
// signals — main's own ctx still comes from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_AUTHZ_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_AUTHZ_DB_PORT", Required: true},
		{Name: "KIBAN_AUTHZ_DB_NAME", Required: true},
		{Name: "KIBAN_AUTHZ_DB_PASSWORD", Required: true},

		{Name: "KEYCLOAK_JWKS_URL", Required: true},
		{Name: "KEYCLOAK_ISSUER_URL", Required: true},
		{Name: "KEYCLOAK_AUDIENCE", Default: "kiban-api"},

		{Name: "KIBAN_IDENTITY_BASE_URL", Default: "http://127.0.0.1:8120"},
		{Name: "KIBAN_REGISTRY_BASE_URL", Default: "http://127.0.0.1:8110"},
		{Name: "KIBAN_ORG_BASE_URL", Default: "http://127.0.0.1:8130"},

		{Name: "KIBAN_AUTHZ_DEBUG_CHECK", Default: "false"},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable&pool_max_conns=16",
		dbUser, values["KIBAN_AUTHZ_DB_PASSWORD"],
		values["KIBAN_AUTHZ_DB_HOST"], values["KIBAN_AUTHZ_DB_PORT"], values["KIBAN_AUTHZ_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := authz.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	auditWriter, err := audit.NewWriter("audit.authz__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	verifier, err := authz.NewTokenVerifier(ctx, values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"])
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}
	go refreshJWKSPeriodically(ctx, logger, verifier)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	identityClient := authz.NewIdentityClient(httpClient, values["KIBAN_IDENTITY_BASE_URL"])
	registryClient := authz.NewRegistryClient(httpClient, values["KIBAN_REGISTRY_BASE_URL"])
	orgClient := authz.NewOrgClient(httpClient, values["KIBAN_ORG_BASE_URL"])

	// kiban_authz_decisions_total{reason} + kiban_authz_decision_duration_seconds, the one
	// service-specific metric family only authz emits (internal/authz/service.go's own
	// evaluate/evaluateBatch wrap decider.Evaluate/EvaluateBatch at the two real enforcement
	// endpoints).
	mreg := metrics.New("authz", version.Version, version.Commit).EnableAuthzDecisions()
	mreg.ObserveDBPool(pool)

	svc := &authz.Service{
		Pool: pool, Audit: auditWriter, Verifier: verifier,
		Identity: identityClient, Registry: registryClient, Org: orgClient,
		KnownEnabled: registryClient.KnownEnabled,
		DebugCheck:   values["KIBAN_AUTHZ_DEBUG_CHECK"] == "true",
		Metrics:      mreg,
	}

	topMux := http.NewServeMux()
	topMux.Handle("GET /metrics", mreg.Handler())
	topMux.Handle("/", svc.Routes())

	handler := httpx.Correlation(
		httpx.Recover(logger)(
			httpx.AccessLog(logger)(
				mreg.Middleware()(topMux),
			),
		),
	)

	listenAddr := values["KIBAN_LISTEN_ADDR"] + ":" + listenPort
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("authz: listening", slog.String("addr", listenAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErr:
		return err
	}
}

func refreshJWKSPeriodically(ctx context.Context, logger *slog.Logger, verifier *authz.TokenVerifier) {
	ticker := time.NewTicker(jwksRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := verifier.Refresh(ctx); err != nil {
				logger.Warn("authz: JWKS refresh failed, keeping last known-good set", slog.Any("error", err))
			}
		}
	}
}
