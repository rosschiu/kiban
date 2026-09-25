// SPDX-License-Identifier: Apache-2.0

// Command registry runs kiban-registry: the platform registry service (module catalog /
// installation / dependency state, the capability API, tenant defaults, seed-missing-only
// bootstrap seeding). It connects to Postgres as its own DB role, kiban_registry — migrations
// run separately, as the kiban owner, via `make migrate-registry`.
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
	"github.com/rosschiu/kiban/internal/registry"
	"github.com/rosschiu/kiban/internal/version"
)

// dbUser is the runtime role migrations/registry creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_registry"

// listenPort is fixed ("127.0.0.1:8110"). The host part is configurable via
// KIBAN_LISTEN_ADDR: defaults to 127.0.0.1 for a host-run process; compose sets
// 0.0.0.0 INSIDE this service's own container (infra/compose.yaml), since it's otherwise
// unreachable from any other container on the compose network. No port beyond the gateway's own
// is published to the HOST (the gateway is the edge) — this only changes what the
// process binds to inside its own container, never what's reachable from outside the host.
const listenPort = "8110"

// builtinModules is the known-manifest set Seed() validates KIBAN_INSTALLED_MODULES against
// (a package variable so tests can substitute it).
var builtinModules = registry.BuiltinModules

func main() {
	logger := obs.New("registry")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("registry: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-registry end to end (config -> DB -> seed -> service -> HTTP listener),
// shutting down gracefully when ctx is cancelled. ctx is a parameter (not created here) so tests
// can drive startup/shutdown deterministically without relying on OS signals — main's own ctx
// still comes from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_REGISTRY_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_REGISTRY_DB_PORT", Required: true},
		{Name: "KIBAN_REGISTRY_DB_NAME", Required: true},
		{Name: "KIBAN_REGISTRY_DB_PASSWORD", Required: true},
		{Name: "KIBAN_INSTALLED_MODULES", Default: ""},
		// Registry's own (defense-in-depth) confirmation that a superadmin
		// mutation caller really is the superadmin — see internal/registry/adminauthz.go.
		{Name: "KIBAN_AUTHZ_BASE_URL", Default: "http://127.0.0.1:8140"},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, values["KIBAN_REGISTRY_DB_PASSWORD"],
		values["KIBAN_REGISTRY_DB_HOST"], values["KIBAN_REGISTRY_DB_PORT"], values["KIBAN_REGISTRY_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := registry.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	store := registry.NewStore(pool)

	installed, err := registry.ParseInstalledModules(values["KIBAN_INSTALLED_MODULES"], builtinModules)
	if err != nil {
		return fmt.Errorf("parse KIBAN_INSTALLED_MODULES: %w", err)
	}
	if err := store.Seed(ctx, builtinModules, installed); err != nil {
		return fmt.Errorf("seed registry: %w", err)
	}
	logger.Info("registry: seed complete", slog.Int("knownModules", len(builtinModules)))

	auditWriter, err := audit.NewWriter("audit.registry__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	adminAuthorizer := registry.NewEffectiveAccessAuthorizer(values["KIBAN_AUTHZ_BASE_URL"], &http.Client{Timeout: 5 * time.Second})
	svc := registry.NewService(store, adminAuthorizer, auditWriter)

	// This service's own GET /metrics, on its own listener — compose-network-internal,
	// never routed through the gateway's module proxy (that only ever mounts `/api/{moduleKey}/
	// {rest...}`; registry isn't even proxied under that pattern — it has its own fixed
	// `/api/platform/*` mount, see internal/gateway/platform_routes.go). mreg.Middleware() wraps
	// topMux DIRECTLY (no request-copy in between) so r.Pattern is visible after routing.
	mreg := metrics.New("registry", version.Version, version.Commit)
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
		logger.Info("registry: listening", slog.String("addr", listenAddr))
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
