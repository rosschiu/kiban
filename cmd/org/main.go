// SPDX-License-Identifier: Apache-2.0

// Command org runs kiban-org: the org service (the triangle — typed org-unit tree,
// company-scoped members with optional user link, position slots). It connects to Postgres as
// its own DB role, kiban_org — migrations run separately, as the kiban owner, via
// `make migrate-org`.
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
	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/org"
	"github.com/rosschiu/kiban/internal/version"
)

// dbUser is the runtime role migrations/org creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_org"

// listenPort is fixed (8130). The host part is configurable via KIBAN_LISTEN_ADDR: defaults to
// 127.0.0.1 for a host-run process; compose sets 0.0.0.0 INSIDE this service's own container
// (infra/compose.yaml). No port beyond the gateway's own is published to the HOST (the gateway
// is the edge).
const listenPort = "8130"

func main() {
	logger := obs.New("org")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("org: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-org end to end (config -> DB -> service -> HTTP listener), shutting down
// gracefully when ctx is cancelled. ctx is a parameter (not created here) so tests can drive
// startup/shutdown deterministically without relying on OS signals — main's own ctx still comes
// from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_ORG_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_ORG_DB_PORT", Required: true},
		{Name: "KIBAN_ORG_DB_NAME", Required: true},
		{Name: "KIBAN_ORG_DB_PASSWORD", Required: true},

		// identity's own base URL — org calls GET /internal/identity/users/{kcSub}/state to
		// validate a link-user request over HTTP, never by trusting input.
		{Name: "KIBAN_IDENTITY_BASE_URL", Default: "http://127.0.0.1:8120"},

		// authz's own base URL, for the real (engine-backed) AdminAuthorizer. Absent ⇒
		// denyAllAuthorizer stays wired (the explicit fail-closed fallback) — never a silent
		// downgrade to "allow".
		{Name: "KIBAN_AUTHZ_BASE_URL", Default: ""},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, values["KIBAN_ORG_DB_PASSWORD"],
		values["KIBAN_ORG_DB_HOST"], values["KIBAN_ORG_DB_PORT"], values["KIBAN_ORG_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := org.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	auditWriter, err := audit.NewWriter("audit.org__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	store := org.NewStore(pool, auditWriter)
	identityClient := org.NewIdentityClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_IDENTITY_BASE_URL"])

	// Real, authz-service-backed AdminAuthorizer when KIBAN_AUTHZ_BASE_URL is
	// configured (both composes already set it); denyAllAuthorizer is the explicit fail-closed
	// fallback when it's absent — never a silent allow.
	var adminAuthorizer org.AdminAuthorizer
	if values["KIBAN_AUTHZ_BASE_URL"] != "" {
		adminAuthorizer = org.NewEngineAdminAuthorizer(values["KIBAN_AUTHZ_BASE_URL"], &http.Client{Timeout: 5 * time.Second})
	} else {
		adminAuthorizer = org.NewDenyAllAuthorizer()
	}

	svc := org.NewService(store, identityClient, adminAuthorizer, auditWriter)

	// This service's own GET /metrics, served on the service listener (see cmd/registry/main.go
	// for the rationale — every service uses the same pattern).
	mreg := metrics.New("org", version.Version, version.Commit)
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
		logger.Info("org: listening", slog.String("addr", listenAddr))
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
