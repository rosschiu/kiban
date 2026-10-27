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
| `gateway` | The only public listener: TLS, token validation, the platform API, the identity provider under `/auth`, the web shell; routes to a sample module when one runs, never to your app. |
| `registry`, `identity`, `org`, `authz` | The foundation services. Internal network only. |
| one container per sample module | `notification`, `docs`, `helpdesk`, `timesheet`; off by default. The `samples` profile starts all four, a module's own profile (`COMPOSE_PROFILES=docs`) starts that one; `KIBAN_INSTALLED_MODULES` must list the same modules. |

Every host-published port binds to `127.0.0.1`: the gateway (8443 in TLS mode, 8090 in plain-HTTP mode; both are published, only the active
mode's port answers), Keycloak
(8081) and Postgres (5434). Put your own reverse proxy or firewall in front for public exposure.
Application containers run as a non-root user with a read-only root filesystem.

## Configuration

`.env` is the environment contract (`.env.example` documents every variable).
`make setup` writes it once with generated secrets and never rewrites it. Secrets that must not
be visible in a process environment are files read through `_FILE` variables: the superadmin's
initial password is a 0600 file under `infra/secrets-in/`, the identity service's client secret
is written by `bootstrap` onto the `kiban-bootstrap-secrets` volume, and the Keycloak admin
password reaches `bootstrap` as a Compose secret. The `keycloak` container itself still receives
its admin password and that client secret as environment variables. The superadmin password is never printed to a log.

Key settings:

- `POSTGRES_USER` (default `postgres`) is the cluster superuser, used only at initialisation and
  by backup tooling. `POSTGRES_DB` must be `kiban`.
- `KIBAN_DB_PASSWORD`: the `kiban` role, non-superuser owner of the application database;
  migrations and bootstrap connect as it. `KC_DB_PASSWORD`: the `keycloak` role, owner of the
  Keycloak database.
- `KIBAN_<SERVICE>_DB_PASSWORD`: every service connects with its own least-privilege role.
- `KIBAN_INSTALLED_MODULES`: which modules the registry installs; a key added later is
  installed on the next restart.
- `KIBAN_SUPERADMIN_USERNAME` / `_EMAIL`: the seeded operator account.
- `KEYCLOAK_REALM`: the realm name. Leave it `kiban`: the imported realm definition names the
  realm by literal.
- `KIBAN_IDENTITY_BASE_URL`: required by the gateway, which provisions users through it.
- `KIBAN_PUBLIC_HOST`: required in public mode (`make public-up`), the hostname the edge serves.
- `KIBAN_EXTRA_ORIGINS`: read by `bootstrap` and by the gateway. Comma-separated extra
  redirect URIs and web origins for `kiban-frontend` on top of `KIBAN_DOMAIN`: an entry with a
  scheme separator (`https://app.example.com`) is a web origin and joins the CORS allow-list; any
  other entry (`com.example.app:/callback`) is a native app's redirect URI.
- `KIBAN_SERVICE_CLIENTS`: read by `bootstrap`; comma-separated ids of confidential Keycloak
  clients with a service account and the `kiban-api` audience, for backends that need their own
  token. See [Getting a token for a service](integrate.md#getting-a-token-for-a-service).
- `KEYCLOAK_DB_NAME`: read by `identity`. When set (the Compose files and the k8s base set
  `keycloak`), every decision reads the user's enabled flag with one `SELECT` from Keycloak's
  own `user_entity` table, as the read-only role `kiban_kcread` that `postgres-init` creates at
  initdb with a default `SELECT` privilege on the tables Keycloak creates. No copy, no sync, no
  lag: a disable is visible the instant Keycloak commits it. The role's password is
  `KIBAN_IDENTITY_DB_PASSWORD`. Unset it when Keycloak uses another database server; identity
  then asks the admin REST API, which costs about 30 ms per decision, behind a cache of
  `KIBAN_USER_STATE_CACHE_SECONDS` (default `5`), so a disable is seen within that many
  seconds. Identity logs which source it uses at start-up, and falls back to the API with a
  warning when the probe fails. This is a deliberate coupling to one column of Keycloak's
  schema, asserted at start-up; see [limitations](limitations.md).
- `KIBAN_ACCESS_TOKEN_LIFESPAN`: read by `bootstrap`; the realm's access-token lifetime in
  seconds, default `300`, written to Keycloak on every run. A disabled user's token verifies
  this long on routes that do not ask for a decision ([limitations](limitations.md)); shorten
  it to narrow that window, at the cost of one refresh per user per lifetime.
- `KIBAN_DOMAIN`: read by `bootstrap` and by the gateway from their own environment, not from
  `.env`. A host name with an optional `:port`, no scheme and no path; the value is not
  validated, and a scheme or path yields redirect URIs and a CORS origin that never match. When set, bootstrap reconciles the `kiban-frontend` client's redirect URIs and web
  origins to exactly `https://<domain>/*` on every run, and the gateway allows that one origin
  for CORS; when unset, bootstrap registers the fixed dev origins (`http://localhost`,
  `http://localhost:3000`, `http://localhost:5173`, `https://127.0.0.1:8443`,
  `https://127.0.0.1:18543`) and the gateway allows the three `localhost` ones for CORS.
  `make public-up` sets it on `bootstrap` and the gateway from `KIBAN_PUBLIC_HOST`; `make dev` leaves it unset, and the image quickstart sets it through its `compose.public.yaml` overlay.
  `KIBAN_EXTRA_ORIGINS` adds to the list.
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
`KIBAN_GATEWAY_HTTP_HOST_PORT`; `docker ps` and `ss -ltn` show what is taken), and
`KIBAN_EXTRA_ORIGINS=https://127.0.0.1:<its TLS port>`, without which Keycloak rejects the
browser login on the new port as an invalid redirect URI. A second
instance is a second Postgres container, never a second database name: `POSTGRES_DB` must stay
`kiban`. `make test-stack-up` does exactly this for the `kiban-test` project.

## What the gateway routes for Keycloak

The gateway is the only public listener and forwards three Keycloak path families, all without
a bearer: `/auth/*` (the login, token and logout endpoints, with Keycloak's absolute URLs
rewritten behind the `/auth` prefix), `/realms/*` (the same realm endpoints, forwarded
untouched; also Keycloak's action pages such as Forgot Password) and `/resources/*` (theme
assets). A login works from either prefix. The discovery document at either prefix names the
issuer `<origin>/realms/<realm>`, which is exactly what every token's `iss` carries, so a
standard OpenID Connect library configured with either discovery URL accepts Kiban's tokens. `/auth/admin*`, `/auth/realms/master*` and `/realms/master*`
answer `404`: the admin console, the admin REST API and the master realm are never on the public
edge. They are reachable only on Keycloak's own host port, `http://127.0.0.1:<KEYCLOAK_HOST_PORT>`
(default `8081`, bound to loopback), as `KC_BOOTSTRAP_ADMIN_USERNAME`.

## TLS

The gateway has two modes, chosen by environment:

1. **Operator certificates**: `KIBAN_TLS_CERT_FILE` and `KIBAN_TLS_KEY_FILE`. Use this for
   air-gapped or internally-signed deployments. `make dev` generates a self-signed pair. Both
   variables are set on the `gateway` service in `infra/compose.yaml`, not read from `.env`:
   mount your pair and point them at it.
2. **Plain HTTP behind your own TLS-terminating reverse proxy**: `KIBAN_INSECURE_HTTP=true` with
   `KIBAN_TRUSTED_PROXY=true` and `KC_HOSTNAME` pinned to the public origin, and both
   certificate variables empty (a configured certificate always wins). This is how
   `make public-up` runs behind a shared Traefik: it expects a Traefik on the existing external
   Docker network `KIBAN_PUBLIC_NETWORK` (default `kiban-public`) with entrypoints `web` and
   `websecure` and a `letsencrypt` certificate resolver, and it turns on the public-demo banner
   (`KIBAN_DEMO_MODE=true`). For another proxy, or without the banner, write your own overlay.

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

## Requiring a second factor

A new realm requires no second factor. The superadmin sets the policy through the gateway and
then pushes it to Keycloak, where the login flow enforces it:

```
# every user: password plus authenticator app (otp); passkey and otp_or_passkey also exist
curl -X PUT $KIBAN/api/platform/admin/mfa-policy/global -H "Authorization: Bearer $SUPERADMIN" \
  -H 'Content-Type: application/json' -d '{"required":true,"method":"otp"}'
curl -X POST $KIBAN/api/platform/admin/mfa-policy/sync -H "Authorization: Bearer $SUPERADMIN"
```

Run the sync after every policy change; it is safe to repeat. A user without the credential is
made to enrol at their next login; a user who has it is challenged for it. A per-user override
(`PUT`/`DELETE .../mfa-policy/users/{subject}`, keyed by the user's Keycloak subject) may only
raise the requirement above the global policy. `GET` on either path reads the effective policy.
A passkey policy enrols a passkey but does not yet challenge for one at login; see
[limitations](limitations.md).

## Backup and restore

Back up two things: the Postgres application database (`pg_dump` of `kiban`; do not use
`pg_dumpall`) and the Keycloak database (`pg_dump` of `keycloak`), both taken as the superuser.
Also keep `.env` and `infra/secrets-in/` somewhere safe: role passwords live only there.
Restore both dumps together into a fresh stack, then start it; rehearse a restore before you
need one. Host `pg_dump` must match the server's major version. Stop the gateways before a
restore that removes users (see limitations: provisioning cache).

## Upgrading

1. Take and verify a backup.
2. Build the new images: `make images-all VERSION=vX.Y.Z` builds all 13. To run released
   images instead, pull each `ghcr.io/rosschiu/kiban-<service>:vX.Y.Z` and `docker tag` it
   `kiban-<service>:vX.Y.Z`; `KIBAN_IMAGE_TAG` only selects images already present locally
   under that name. `make pin-images` refreshes the digest pins on third-party base images.
3. Start with the tag: `KIBAN_IMAGE_TAG=vX.Y.Z make dev` (or `make public-up`). Migrations are
   forward-only and applied automatically before the services start; shipped migrations are
   checksummed, and `make validate-migrations` (part of `make check`) fails if one was altered;
   nothing checks this at deploy time.
4. Check `docker compose --env-file .env --project-directory infra ps` and the `bootstrap`
   container's log: one `bootstrap: step result` line per step.

Rollback is a restore of the backup and a redeploy of the previous tag, never a downward
migration.

A stack created before the database roles change (the `kiban` owner role, `KIBAN_DB_PASSWORD`,
`KC_DB_PASSWORD`) cannot be upgraded in place: recreate it (`make dev-clean && make dev`) or dump
and restore into a fresh cluster.

A cluster created before 0.2.0 has no `kiban_kcread` role, so identity logs a warning and keeps
using the admin REST API. To switch it to the direct read without recreating the cluster, run
once as the Postgres superuser, with identity's password:

```sql
CREATE ROLE kiban_kcread LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '<KIBAN_IDENTITY_DB_PASSWORD>';
GRANT CONNECT ON DATABASE keycloak TO kiban_kcread;
\c keycloak
GRANT USAGE ON SCHEMA public TO kiban_kcread;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO kiban_kcread;
ALTER DEFAULT PRIVILEGES FOR ROLE keycloak IN SCHEMA public GRANT SELECT ON TABLES TO kiban_kcread;
```

then restart identity.

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
`DELETE` at the database level; a `correlation_id` matches the `correlationId` field the gateway
logged for the request (its `x-correlation-id` header), so a request can be followed from the gateway log into every table it
touched.

## Observability

The platform is one Prometheus scrape target: `GET /api/platform/metrics` on the gateway, with
a superadmin bearer, returns every service's and enabled module's metrics in one exposition,
each series labeled `service`, plus `kiban_metrics_scrape_up{service}` per target (`0` when a
service did not answer; the response itself is always `200`). Each service except the gateway also keeps its own
`/metrics` on its internal listener for a Prometheus inside the network. See
[Metrics](metrics.md). Logs are JSON on stderr with a `correlationId` field per request.
`kiban_build_info{version,commit}` tells you exactly what is running.

## Health

`/health` on each service answers as soon as the process is up; `/ready` also pings the
database. Compose health checks and the Kubernetes readiness probes use `/ready`, so a service
that has lost its database is reported unhealthy and recovers on its own when the database
returns. The gateway is checked on `/`.
