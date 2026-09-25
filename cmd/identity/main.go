// SPDX-License-Identifier: Apache-2.0

// Command identity runs kiban-identity: the identity service (canonical Keycloak-subject-keyed
// user records, platform roles, login observation, MFA policy layering synced to Keycloak). It
// connects to Postgres as its own DB role, kiban_identity — migrations run separately, as the
// kiban owner, via `make migrate-identity`.
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
	"github.com/rosschiu/kiban/internal/identity"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/version"
)

// keycloakClientID is the confidential service-account client internal/bootstrap creates in
// the realm (identityServiceClientID there) — fixed, not an env knob (its secret stays one).
const keycloakClientID = "kiban-identity-service"

// dbUser is the runtime role migrations/identity creates and grants — fixed, not an env knob
// (the password stays one).
const dbUser = "kiban_identity"

// listenPort is fixed. The host part is configurable via KIBAN_LISTEN_ADDR: defaults to
// 127.0.0.1 for a host-run process; compose sets 0.0.0.0 INSIDE this service's own container
// (infra/compose.yaml). No port beyond the gateway's own is published to the HOST (the gateway
// is the edge).
const listenPort = "8120"

// jwksRefreshInterval controls how often the token verifier re-fetches Keycloak's JWKS to pick
// up key rotation.
const jwksRefreshInterval = 10 * time.Minute

func main() {
	logger := obs.New("identity")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("identity: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-identity end to end (config -> DB -> Keycloak verifier/admin client ->
// service -> HTTP listener), shutting down gracefully when ctx is cancelled. ctx is a parameter
// (not created here) so tests can drive startup/shutdown deterministically without relying on
// OS signals — main's own ctx still comes from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: "127.0.0.1"},
		{Name: "KIBAN_IDENTITY_DB_HOST", Default: "127.0.0.1"},
		{Name: "KIBAN_IDENTITY_DB_PORT", Required: true},
		{Name: "KIBAN_IDENTITY_DB_NAME", Required: true},
		{Name: "KIBAN_IDENTITY_DB_PASSWORD", Required: true},

		// Keycloak integration:
		{Name: "KEYCLOAK_BASE_URL", Required: true},   // e.g. http://127.0.0.1:8081
		{Name: "KEYCLOAK_JWKS_URL", Required: true},   // e.g. {BASE_URL}/realms/{REALM}/protocol/openid-connect/certs
		{Name: "KEYCLOAK_ISSUER_URL", Required: true}, // token `iss` must match exactly
		{Name: "KEYCLOAK_REALM", Required: true},
		{Name: "KEYCLOAK_AUDIENCE", Default: "kiban-api"},

		// Dedicated service-account client (never master-realm credentials at runtime) —
		// secret arrives via the *_FILE convention (config.Load).
		{Name: "KEYCLOAK_IDENTITY_CLIENT_SECRET", Required: true},

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
		dbUser, values["KIBAN_IDENTITY_DB_PASSWORD"],
		values["KIBAN_IDENTITY_DB_HOST"], values["KIBAN_IDENTITY_DB_PORT"], values["KIBAN_IDENTITY_DB_NAME"],
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := identity.CheckMigrationsApplied(ctx, pool); err != nil {
		return err
	}

	store := identity.NewStore(pool)

	verifier, err := identity.NewTokenVerifier(ctx, values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"])
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}
	go refreshJWKSPeriodically(ctx, logger, verifier)

	adminClient := identity.NewAdminClient(
		&http.Client{Timeout: 5 * time.Second},
		values["KEYCLOAK_BASE_URL"], values["KEYCLOAK_REALM"],
		keycloakClientID, values["KEYCLOAK_IDENTITY_CLIENT_SECRET"],
	)

	auditWriter, err := audit.NewWriter("audit.identity__events")
	if err != nil {
		return fmt.Errorf("build audit writer: %w", err)
	}

	// Real, authz-service-backed AdminAuthorizer when KIBAN_AUTHZ_BASE_URL is
	// configured (both composes already set it); denyAllAuthorizer is the explicit fail-closed
	// fallback when it's absent — never a silent allow.
	var adminAuthorizer identity.AdminAuthorizer
	if values["KIBAN_AUTHZ_BASE_URL"] != "" {
		adminAuthorizer = identity.NewEngineAdminAuthorizer(values["KIBAN_AUTHZ_BASE_URL"], &http.Client{Timeout: 5 * time.Second})
	} else {
		adminAuthorizer = identity.NewDenyAllAuthorizer()
	}

	svc := identity.NewService(store, adminClient, verifier, adminAuthorizer, auditWriter)

	// This service's own GET /metrics, on the same listener (see cmd/registry/main.go's own
	// comment for the full rationale — same pattern every service uses).
	mreg := metrics.New("identity", version.Version, version.Commit)
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
		logger.Info("identity: listening", slog.String("addr", listenAddr))
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

// refreshJWKSPeriodically re-fetches the JWKS on a fixed interval until ctx is done. A failed
// refresh is logged and the previous key set keeps serving (see TokenVerifier.Refresh).
func refreshJWKSPeriodically(ctx context.Context, logger *slog.Logger, verifier *identity.TokenVerifier) {
	ticker := time.NewTicker(jwksRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := verifier.Refresh(ctx); err != nil {
				logger.Warn("identity: jwks refresh failed", slog.Any("error", err))
			}
		}
	}
}
