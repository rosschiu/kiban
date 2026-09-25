# Operating Kiban

Everything an operator needs for a single-host Compose deployment. Kubernetes manifests exist in
`deploy/k8s/` (hardened, readiness-probed, proven on a local kind cluster), but Compose is the
supported path for 0.1.

## The stack

| Container | Role |
|---|---|
| `postgres` | System of record for every service, including authorization tuples. Postgres 18. |
| `keycloak` | Embedded identity provider. Keycloak 26 with the imported realm and Kiban's MFA-setup authenticator. |
| `migrate` | One-shot: applies each service's SQL migrations in order, under a lock, as the `kiban` owner role. |
| `bootstrap` | One-shot: reconciles the realm, seeds the superadmin once, seeds default grants. Safe to re-run; it converges and never overwrites runtime state. |
| `gateway` | The only public listener: TLS, token validation, module routing, the identity provider under `/auth`, the web shell. |
| `registry`, `identity`, `org`, `authz` | The foundation services. Internal network only. |
| one container per module | `notification`, `docs`, `helpdesk`, `timesheet` in the default set. |

Every host-published port binds to `127.0.0.1`: the gateway (8443 TLS, 8090 plain), Keycloak
(8081) and Postgres (5434). Put your own reverse proxy or firewall in front for public exposure.
Application containers run as a non-root user with a read-only root filesystem.

## Configuration

`.env` is the environment contract (`.env.example` documents every variable).
`make setup` writes it once with generated secrets and never rewrites it. Secrets that must not
be visible in a process environment, such as the superadmin's initial password and the identity
service's client secret, are files under `infra/secrets-in/` with mode 0600; services read them
through `_FILE` variables. The superadmin password is never printed to a log.

Key settings:

- `POSTGRES_USER` (default `postgres`) is the cluster superuser, used only at initialisation and
  by backup tooling. `POSTGRES_DB` must be `kiban`.
- `KIBAN_DB_PASSWORD`: the `kiban` role, non-superuser owner of the application database;
  migrations and bootstrap connect as it. `KC_DB_PASSWORD`: the `keycloak` role, owner of the
  Keycloak database.
- `KIBAN_<SERVICE>_DB_PASSWORD`: every service connects with its own least-privilege role.
- `KIBAN_INSTALLED_MODULES`: which modules the registry installs at first boot.
- `KIBAN_SUPERADMIN_USERNAME` / `_EMAIL`: the seeded operator account.
- `KEYCLOAK_REALM`: the realm name (default `kiban`).
- `KIBAN_IDENTITY_BASE_URL`: required by the gateway, which provisions users through it.
- `KIBAN_PUBLIC_HOST`: required in public mode (`make public-up`), the hostname the edge serves.
- `KIBAN_DOMAIN`: read by `bootstrap` and by the gateway from their own environment, not from
  `.env`. When set, bootstrap reconciles the `kiban-frontend` client's redirect URIs and web
  origins to exactly `https://<domain>/*` on every run, and the gateway allows that one origin
  for CORS; when unset, both use the fixed localhost set. `make public-up` sets it on
  `bootstrap` from `KIBAN_PUBLIC_HOST`; `make dev` and the image quickstart leave it unset. There
  is no variable for an extra origin.
- `KEYCLOAK_AUDIENCE` (default `kiban-api`): the audience every service requires in a bearer.
  The realm's audience mapper on `kiban-frontend` writes `kiban-api`, and the Compose files do
  not pass this variable through, so it only matters for a compose file of your own.
- `KIBAN_MODULE_HOST_<KEY>`: on the gateway, the host name it dials for module `<key>`
  (`KIBAN_MODULE_HOST_NOTIFICATION: notification` in `infra/compose.yaml`). Without it the
  gateway dials `127.0.0.1:<port>`, the host-run layout, which is not the module's container.
  Set in the compose file, not in `.env`.

### Running a second instance on the same host

`infra/compose.yaml` names its Compose project `kiban`. To run an independent instance from a
second checkout, give that checkout's `.env` its own `COMPOSE_PROJECT_NAME` and a free port set
(`POSTGRES_HOST_PORT`, `KEYCLOAK_HOST_PORT`, `KIBAN_GATEWAY_TLS_HOST_PORT`,
`KIBAN_GATEWAY_HTTP_HOST_PORT`; `docker ps` and `ss -ltn` show what is taken). A second
instance is a second Postgres container, never a second database name: `POSTGRES_DB` must stay
`kiban`. `make test-stack-up` does exactly this for the `kiban-test` project.

## What the gateway routes for Keycloak

The gateway is the only public listener and forwards three Keycloak path families, all without
a bearer: `/auth/*` (the login, token and logout endpoints, with Keycloak's absolute URLs
rewritten to the gateway origin), `/realms/*` (action pages such as Forgot Password) and
`/resources/*` (theme assets). `/auth/admin*`, `/auth/realms/master*` and `/realms/master*`
answer `404`: the admin console, the admin REST API and the master realm are never on the public
edge. They are reachable only on Keycloak's own host port, `http://127.0.0.1:<KEYCLOAK_HOST_PORT>`
(default `8081`, bound to loopback), as `KC_BOOTSTRAP_ADMIN_USERNAME`.

## TLS

The gateway has two modes, chosen by environment:

1. **Operator certificates**: `KIBAN_TLS_CERT_FILE` and `KIBAN_TLS_KEY_FILE`. Use this for
   air-gapped or internally-signed deployments. `make dev` generates a self-signed pair.
2. **Plain HTTP behind your own TLS-terminating reverse proxy**: `KIBAN_INSECURE_HTTP=true` with
   `KIBAN_TRUSTED_PROXY=true` and `KC_HOSTNAME` pinned to the public origin. This is how
   `make public-up` runs behind a shared Traefik.

The gateway does not obtain certificates itself. `KIBAN_DOMAIN` only names the public origin
(redirect URIs, CORS); it does not select a TLS mode.

## Identity federation

Kiban's Keycloak realm accepts external identity providers as login sources. Configure them in
the Keycloak admin console, reachable only on Keycloak's own host port (see above). Federation means login and identity only; Kiban never manages your
provider's directory.

## First login and users

The superadmin is created by bootstrap with the password from `infra/secrets-in/`. Keycloak
forces a password change on first login. The realm enforces a password policy (12 characters
minimum, not the username or email) and locks an account temporarily after ten failed attempts.

A user created in Keycloak is provisioned in Kiban by the gateway on that user's first
request. Company membership is a separate administrator action.

## Backup and restore

Back up two things: the Postgres application database (`pg_dump` of `kiban`; do not use
`pg_dumpall`) and the Keycloak database (`pg_dump` of `keycloak`), both taken as the superuser.
Also keep `.env` and `infra/secrets-in/` somewhere safe: role passwords live only there.
Restore both dumps together into a fresh stack, then start it; rehearse a restore before you
need one. Host `pg_dump` must match the server's major version. Stop the gateways before a
restore that removes users (see limitations: provisioning cache).

## Upgrading

1. Take and verify a backup.
2. Build or pull the new images (`make images-all VERSION=vX.Y.Z` builds all 13, or set
   `KIBAN_IMAGE_TAG`). `make pin-images` refreshes the digest pins on third-party base images.
3. Start with the tag: `KIBAN_IMAGE_TAG=vX.Y.Z make dev` (or `make public-up`). Migrations are
   forward-only and applied automatically before the services start; shipped migrations are
   checksummed (`make validate-migrations`) and refuse to run if altered.
4. Check `docker compose ps` and the audit tables for the bootstrap run.

Rollback is a restore of the backup and a redeploy of the previous tag, never a downward
migration.

A stack created before the database roles change (the `kiban` owner role, `KIBAN_DB_PASSWORD`,
`KC_DB_PASSWORD`) cannot be upgraded in place: recreate it (`make dev-clean && make dev`) or dump
and restore into a fresh cluster.

## Reading the audit trail

There is no API for the audit trail. Every service writes its events into its own append-only
table in the `audit` schema, one row per mutation in the same transaction:
`audit.registry__events`, `audit.identity__events`, `audit.org__events`,
`audit.authz__events`, and one per module (`audit.notification__events`,
`audit.timesheet__events`, `audit.docs__events`, `audit.helpdesk__events`). Each row has `id`,
`occurred_at`, `actor` (from the verified token), `action`, `subject`, a `payload` (JSON) and
`correlation_id`. Connect as the database owner `kiban` on the host-published port:

```
psql "postgres://kiban:${KIBAN_DB_PASSWORD}@127.0.0.1:${POSTGRES_HOST_PORT:-5434}/kiban" \
  -c "select occurred_at, actor, action, subject, correlation_id from audit.org__events order by id desc limit 20"
```

`KIBAN_DB_PASSWORD` and `POSTGRES_HOST_PORT` are in `.env`. The tables refuse `UPDATE` and
`DELETE` at the database level; a `correlation_id` matches the `x-correlation-id` the gateway
logged for the request, so a request can be followed from the gateway log into every table it
touched.

## Observability

The platform is one Prometheus scrape target: `GET /api/platform/metrics` on the gateway, with
a superadmin bearer, returns every service's and enabled module's metrics in one exposition,
each series labeled `service`, plus `kiban_metrics_scrape_up{service}` per target (`0` when a
service did not answer; the response itself is always `200`). Each service also keeps its own
`/metrics` on its internal listener for a Prometheus inside the network. See
[Metrics](metrics.md). Logs are JSON on stdout with a correlation id per request.
`kiban_build_info{version,commit}` tells you exactly what is running.

## Health

`/health` on each service answers as soon as the process is up; `/ready` also pings the
database. Compose health checks and the Kubernetes readiness probes use `/ready`, so a service
that has lost its database is reported unhealthy and recovers on its own when the database
returns. The gateway is checked on `/`.
