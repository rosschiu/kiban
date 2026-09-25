// SPDX-License-Identifier: Apache-2.0

// Command helpdesk runs kiban-helpdesk: the helpdesk module service's HTTP API (ticket
// workflow). It connects to Postgres as its own DB role, kiban_helpdesk —
// migrations run separately, as the kiban owner, via `make migrate-helpdesk`.
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

	helpdesk "github.com/rosschiu/kiban/modules/helpdesk/service"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/version"
	"github.com/rosschiu/kiban/modulekit"
)

// dbUser is the runtime role modules/helpdesk/migrations creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_helpdesk"

// listenPort matches module.manifest.json's service.port — kept in sync by hand; the module
// validator checks the manifest's port range and catalog uniqueness, not this constant.
const listenPort = "8180"

func main() {
	logger := obs.New("helpdesk")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("helpdesk: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_HELPDESK_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_HELPDESK_DB_PORT", Required: true},
		{Name: "KIBAN_HELPDESK_DB_NAME", Required: true},
		{Name: "KIBAN_HELPDESK_DB_PASSWORD", Required: true},

		{Name: "KEYCLOAK_JWKS_URL", Required: true},
		{Name: "KEYCLOAK_ISSUER_URL", Required: true},
		{Name: "KEYCLOAK_AUDIENCE", Default: "kiban-api"},

		// Per-operation authorization (company_module tier checks) and grant/revoke tuple
		// writes (the agent tier) both go through authz's own S2S surface.
		{Name: "KIBAN_AUTHZ_BASE_URL", Default: "http://127.0.0.1:8140"},
		// Member-directory/GetMember facts (assignee/agent target resolution to kcSub).
		{Name: "KIBAN_ORG_BASE_URL", Default: "http://127.0.0.1:8130"},
		// Assignment/status-change/comment fire a targeted notification event —
		// non-fatal if unreachable.
		{Name: "KIBAN_NOTIFICATION_BASE_URL", Default: "http://127.0.0.1:8150"},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, values["KIBAN_HELPDESK_DB_PASSWORD"],
		values["KIBAN_HELPDESK_DB_HOST"], values["KIBAN_HELPDESK_DB_PORT"], values["KIBAN_HELPDESK_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := helpdesk.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	auditWriter, err := audit.NewWriter("audit.helpdesk__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	verifier, err := helpdesk.NewTokenVerifier(ctx, values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"])
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}

	store := helpdesk.NewStore(pool, auditWriter)
	authzClient := helpdesk.NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_AUTHZ_BASE_URL"])
	orgClient := helpdesk.NewOrgClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_ORG_BASE_URL"])
	notifClient := helpdesk.NewNotificationClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_NOTIFICATION_BASE_URL"])
	svc := helpdesk.NewService(store, verifier, authzClient, orgClient, notifClient)

	go verifier.RefreshPeriodically(ctx, logger, modulekit.DefaultJWKSRefreshInterval)

	// This service's own GET /metrics, on its own listener (see cmd/registry/main.go's
	// own comment for the full rationale — same pattern every service uses).
	mreg := metrics.New("helpdesk", version.Version, version.Commit)
	mreg.ObserveDBPool(pool)
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
		logger.Info("helpdesk: listening", slog.String("addr", listenAddr))
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
