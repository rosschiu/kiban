// SPDX-License-Identifier: Apache-2.0

// Command notification runs kiban-notification: the notification module service —
// channels/subscriptions/messages/inbox HTTP API plus the leased delivery worker, in one process
// (the module manifest names one service.port; the worker is an in-process background loop, not a
// second binary). It connects to Postgres as its own DB role, kiban_notification — migrations
// run separately, as the kiban owner, via `make migrate-notification`.
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

	notification "github.com/rosschiu/kiban/modules/notification/service"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/version"
	"github.com/rosschiu/kiban/modulekit"
)

// smtpFrom is the envelope sender for every email delivery — fixed, not an env knob.
const smtpFrom = "notification@kiban.local"

// dbUser is the runtime role modules/notification/migrations creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_notification"

// listenPort matches module.manifest.json's service.port — kept in sync by hand; the module
// validator checks the manifest's port range and catalog uniqueness, not this constant. Host part configurable via KIBAN_LISTEN_ADDR, same convention
// every foundation service uses.
const listenPort = "8150"

func main() {
	logger := obs.New("notification")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("notification: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_NOTIFICATION_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_NOTIFICATION_DB_PORT", Required: true},
		{Name: "KIBAN_NOTIFICATION_DB_NAME", Required: true},
		{Name: "KIBAN_NOTIFICATION_DB_PASSWORD", Required: true},

		// The delivery_job claim_group this process's worker (and its own SendMessage
		// writes) is scoped to. Always "default" in production — a module's own test suite binds
		// its own Store to a unique per-run group instead, so it never races this container's
		// worker for the same rows.
		{Name: "KIBAN_NOTIFICATION_CLAIM_GROUP", Default: "default"},

		{Name: "KEYCLOAK_JWKS_URL", Required: true},
		{Name: "KEYCLOAK_ISSUER_URL", Required: true},
		{Name: "KEYCLOAK_AUDIENCE", Default: "kiban-api"},

		// authz's own base URL — per-operation authorization goes through authz's real
		// effective-access decision (which itself calls org's company-facts endpoint as part of its own
		// step 5).
		{Name: "KIBAN_AUTHZ_BASE_URL", Default: "http://127.0.0.1:8140"},

		// The targeted-events S2S endpoint confirms each recipient kcSub is an active
		// company member via org's own membership fact endpoint (same default port every other
		// service's KIBAN_ORG_BASE_URL points at, e.g. modules/timesheet/service/cmd/main.go).
		{Name: "KIBAN_ORG_BASE_URL", Default: "http://127.0.0.1:8130"},

		// SMTP goes through net/smtp to a mailpit container (dev), never a vendor SDK.
		{Name: "KIBAN_NOTIFICATION_SMTP_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_NOTIFICATION_SMTP_PORT", Default: "1025"},
		{Name: "KIBAN_NOTIFICATION_WEBHOOK_HMAC_SECRET", Required: true},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, values["KIBAN_NOTIFICATION_DB_PASSWORD"],
		values["KIBAN_NOTIFICATION_DB_HOST"], values["KIBAN_NOTIFICATION_DB_PORT"], values["KIBAN_NOTIFICATION_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := notification.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	auditWriter, err := audit.NewWriter("audit.notification__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	verifier, err := notification.NewTokenVerifier(ctx, values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"])
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}

	// The webhook policy reads its own env directly (KIBAN_WEBHOOK_ALLOW_HTTP,
	// KIBAN_WEBHOOK_ALLOWED_HOSTS) — both optional, so no config.Spec entry is needed here; the
	// same policy instance is handed to the Store so CreateChannel's create-time check and the
	// worker's delivery-time re-check agree.
	webhookPolicy := notification.NewWebhookPolicyFromEnv()
	store := notification.NewStore(pool, auditWriter, values["KIBAN_NOTIFICATION_CLAIM_GROUP"], webhookPolicy)
	authzClient := notification.NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_AUTHZ_BASE_URL"])
	svc := notification.NewService(store, verifier, authzClient)
	svc.Org = notification.NewOrgClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_ORG_BASE_URL"])

	mailer := notification.NewMailer(values["KIBAN_NOTIFICATION_SMTP_HOST"], values["KIBAN_NOTIFICATION_SMTP_PORT"], smtpFrom)
	webhook := notification.NewWebhookSender(webhookPolicy, values["KIBAN_NOTIFICATION_WEBHOOK_HMAC_SECRET"])

	// kiban_delivery_jobs{state} + kiban_delivery_attempts_total{kind,outcome}, the
	// service-specific family only notification emits (worker.go's own reportJobCounts/
	// deliverLeased/failJob).
	mreg := metrics.New("notification", version.Version, version.Commit).EnableDeliveryJobs()
	mreg.ObserveDBPool(pool)

	worker := notification.NewWorker(store, mailer, webhook, logger)
	worker.Metrics = mreg
	go worker.Run(ctx)

	// Periodic JWKS refresh (same shape as cmd/gateway/main.go's refreshJWKSPeriodically), so a
	// rotated IdP key is picked up without restarting this process.
	go verifier.RefreshPeriodically(ctx, logger, modulekit.DefaultJWKSRefreshInterval)

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
		logger.Info("notification: listening", slog.String("addr", listenAddr))
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
