// SPDX-License-Identifier: Apache-2.0

// Command gateway runs kiban-gateway, the edge service. JWKS bearer validation, the
// registry-driven dynamic module proxy with capability enforcement, the superadmin guard, the
// `/auth` Keycloak reverse proxy and static SPA serving live in internal/gateway. This file wires
// TLS mode selection (operator certs / plain HTTP behind a TLS-terminating proxy or in dev).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rosschiu/kiban/internal/config"
	"github.com/rosschiu/kiban/internal/gateway"
	"github.com/rosschiu/kiban/internal/httpx"
	"github.com/rosschiu/kiban/internal/obs"
	"github.com/rosschiu/kiban/internal/obs/metrics"
	"github.com/rosschiu/kiban/internal/version"
)

// defaultListenHost is used when KIBAN_LISTEN_ADDR is unset — every published port stays
// localhost-only for a host-run process. Compose sets KIBAN_LISTEN_ADDR=0.0.0.0 INSIDE each
// container (see infra/compose.yaml); the container's published host port still binds
// 127.0.0.1 only (see the gateway service's `ports:` entries) — this env var changes what the
// process inside the container binds to, never what's reachable from outside the host.
const defaultListenHost = "127.0.0.1"

// jwksRefreshInterval controls how often the token verifier re-fetches Keycloak's JWKS to pick
// up key rotation (same shape identity/authz/org already use).
const jwksRefreshInterval = 10 * time.Minute

// shutdownTimeout bounds graceful shutdown of the listener this process runs.
const shutdownTimeout = 5 * time.Second

// tlsPort and devHTTPPort are the two listener ports (TLS mode picks which one is bound) —
// fixed: infra/compose.yaml, compose.public.yaml and deploy/k8s all publish these literals.
const (
	tlsPort     = "8443"
	devHTTPPort = "8090"
)

func main() {
	logger := obs.New("gateway")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("gateway: fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires kiban-gateway end to end (config -> Keycloak verifier -> routes -> TLS mode
// selection -> listener), shutting down gracefully when ctx is cancelled. ctx is a parameter
// (not created here) so tests can drive startup/shutdown deterministically without relying on OS
// signals — main's own ctx still comes from signal.NotifyContext, unchanged in behavior.
func run(ctx context.Context, logger *slog.Logger) error {
	values, err := config.Load(config.Spec{
		{Name: "KIBAN_LISTEN_ADDR", Default: defaultListenHost},

		// Keycloak integration.
		{Name: "KEYCLOAK_BASE_URL", Required: true},   // e.g. http://127.0.0.1:8081 — /auth proxy target
		{Name: "KEYCLOAK_JWKS_URL", Required: true},   // e.g. {BASE_URL}/realms/{REALM}/protocol/openid-connect/certs
		{Name: "KEYCLOAK_ISSUER_URL", Required: true}, // token `iss` must match exactly
		{Name: "KEYCLOAK_AUDIENCE", Default: "kiban-api"},

		{Name: "KIBAN_REGISTRY_BASE_URL", Default: "http://127.0.0.1:8110"},
		// Bounds how long the gateway keeps routing on a stale catalog snapshot
		// while the registry is unreachable, before failing closed (503 MODULE_UNAVAILABLE).
		// Parsed with time.ParseDuration — e.g. "60s", "2m".
		{Name: "KIBAN_CATALOG_MAX_STALE", Default: "60s"},
		{Name: "KIBAN_AUTHZ_BASE_URL", Default: "http://127.0.0.1:8140"},
		// The foundation routes' org target (`/api/org/me/companies`).
		{Name: "KIBAN_ORG_BASE_URL", Default: "http://127.0.0.1:8130"},
		// First-request provisioning target (internal/gateway.Provisioner): every subject is
		// resolved through identity before its first request proceeds. Required (no default): a
		// gateway that cannot provision must not start and silently 503 every user.
		{Name: "KIBAN_IDENTITY_BASE_URL", Required: true}, // e.g. http://identity:8120
		{Name: "KIBAN_STATIC_DIR", Default: ""},
		// Demo-mode banner flag — off unless the deploying operator explicitly sets
		// this true (the public demo's own compose override). Never inferred from KIBAN_DOMAIN.
		{Name: "KIBAN_DEMO_MODE", Default: "false"},

		// KIBAN_DOMAIN has no TLS meaning: it only feeds the CORS allowed origin here (and
		// bootstrap's redirect URIs). TLS: operator-supplied certs, else plain HTTP requiring the
		// explicit KIBAN_INSECURE_HTTP opt-in (dev, or behind a TLS-terminating proxy).
		{Name: "KIBAN_DOMAIN", Default: ""},
		{Name: "KIBAN_TLS_CERT_FILE", Default: ""},
		{Name: "KIBAN_TLS_KEY_FILE", Default: ""},
		{Name: "KIBAN_INSECURE_HTTP", Default: "false"},
		// Trust inbound X-Forwarded-Proto/-Host on the /auth proxy — ONLY behind a TLS-
		// terminating edge that overwrites these headers itself (compose.public.yaml's
		// shared Traefik); see internal/gateway.NewAuthProxy.
		{Name: "KIBAN_TRUSTED_PROXY", Default: "false"},
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	verifier, err := gateway.NewTokenVerifier(ctx, values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"])
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}
	go refreshJWKSPeriodically(ctx, logger, verifier, jwksRefreshInterval)

	catalogMaxStale, err := time.ParseDuration(values["KIBAN_CATALOG_MAX_STALE"])
	if err != nil {
		return fmt.Errorf("parse KIBAN_CATALOG_MAX_STALE: %w", err)
	}
	catalog := gateway.NewCatalogClient(values["KIBAN_REGISTRY_BASE_URL"], logger)
	catalog.MaxStale = catalogMaxStale
	adminClient := gateway.NewAuthzAdminClient(values["KIBAN_AUTHZ_BASE_URL"])

	// The gateway has no DB pool of its own (no ObserveDBPool call), so its own /metrics
	// (routes.go) and the operator-only /api/platform/metrics (platform_routes.go) both expose
	// exactly: the standard HTTP set, kiban_build_info, and EnableGatewayUpstream's
	// kiban_gateway_upstream_* (wired into internal/gateway.ModuleProxy via RoutesConfig.Metrics
	// -> proxy.Metrics).
	mreg := metrics.New("gateway", version.Version, version.Commit).EnableGatewayUpstream()

	handler := httpx.Correlation(
		httpx.Recover(logger)(
			httpx.AccessLog(logger)(
				// mreg.Middleware() wraps gateway.Routes(cfg) DIRECTLY — no request-object copy
				// happens between here and the mux inside it (CORS, routes.go's outermost wrap,
				// never calls r.WithContext), so r.Pattern set by ServeMux during routing is still
				// visible here after next.ServeHTTP returns (metrics.Registry.Middleware's own
				// doc comment has the full account).
				mreg.Middleware()(gateway.Routes(gateway.RoutesConfig{
					Verifier:          verifier,
					Catalog:           catalog,
					RegistryBaseURL:   values["KIBAN_REGISTRY_BASE_URL"],
					KeycloakBaseURL:   values["KEYCLOAK_BASE_URL"],
					AuthzBaseURL:      values["KIBAN_AUTHZ_BASE_URL"],
					OrgBaseURL:        values["KIBAN_ORG_BASE_URL"],
					IdentityBaseURL:   values["KIBAN_IDENTITY_BASE_URL"],
					Logger:            logger,
					AdminClient:       adminClient,
					StaticDir:         values["KIBAN_STATIC_DIR"],
					KibanDomain:       values["KIBAN_DOMAIN"],
					TrustProxyHeaders: values["KIBAN_TRUSTED_PROXY"] == "true",
					IssuerURL:         values["KEYCLOAK_ISSUER_URL"],
					Metrics:           mreg,
					DemoMode:          values["KIBAN_DEMO_MODE"] == "true",
				})),
			),
		),
	)

	tlsConfig, err := buildTLSConfig(values)
	if err != nil {
		return fmt.Errorf("build TLS config: %w", err)
	}

	host := values["KIBAN_LISTEN_ADDR"]

	if tlsConfig != nil {
		return serveTLS(ctx, logger, handler, tlsConfig, host+":"+tlsPort)
	}
	if values["KIBAN_INSECURE_HTTP"] != "true" {
		return fmt.Errorf("no TLS configured (set KIBAN_TLS_CERT_FILE+KIBAN_TLS_KEY_FILE, or " +
			"KIBAN_INSECURE_HTTP=true behind a TLS-terminating proxy) — refusing to serve plaintext by default")
	}
	return serveDevHTTP(ctx, logger, handler, host+":"+devHTTPPort)
}

// serveTLS runs the TLS listener, shutting it down on ctx cancellation.
func serveTLS(ctx context.Context, logger *slog.Logger, handler http.Handler, tlsConfig *tls.Config, addr string) error {
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return serve(ctx, server, func() error {
		logger.Info("gateway: listening (TLS)", slog.String("addr", addr))
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("tls listener: %w", err)
		}
		return nil
	})
}

// serveDevHTTP runs the dev-only plain-HTTP listener (KIBAN_INSECURE_HTTP=true).
func serveDevHTTP(ctx context.Context, logger *slog.Logger, handler http.Handler, addr string) error {
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return serve(ctx, server, func() error {
		logger.Info("gateway: listening (dev-mode HTTP, no TLS)", slog.String("addr", addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
}

// serve runs listen in a goroutine and returns its error, or the graceful-shutdown result once
// ctx is cancelled.
func serve(ctx context.Context, server *http.Server, listen func() error) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- listen() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErr:
		return err
	}
}

// refreshJWKSPeriodically re-fetches the JWKS on a fixed interval until ctx is done. A failed
// refresh is logged and the previous key set keeps serving (see TokenVerifier.Refresh). interval
// is a parameter (production always passes the package's own jwksRefreshInterval) purely so
// tests can drive the ticker.C branch deterministically without waiting 10 real minutes.
func refreshJWKSPeriodically(ctx context.Context, logger *slog.Logger, verifier *gateway.TokenVerifier, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := verifier.Refresh(ctx); err != nil {
				logger.Warn("gateway: jwks refresh failed", slog.Any("error", err))
			}
		}
	}
}
