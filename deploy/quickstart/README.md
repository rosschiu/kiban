# Kiban zero-clone quickstart

Run Kiban with no `git clone`, no `make` and no build: every service is pulled straight from
`ghcr.io/rosschiu`. You need two files, two settings, and one command.

## 1. Download two files

```
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/rosschiu/kiban/main/deploy/quickstart/docker-compose.yml
curl -fsSL -o .env.example       https://raw.githubusercontent.com/rosschiu/kiban/main/deploy/quickstart/.env.example
cp .env.example .env
```

## 2. Set two things

**a. `KIBAN_VERSION`** in `.env`: the published image tag to run. It defaults to `v0.1.0`; see
the [available tags](https://github.com/rosschiu/kiban/pkgs/container/kiban-gateway).

**b. Every secret field** in `.env`. They are all blank by default, because no passwords are
baked in (the full repo's root `.env.example` works the same way). Generate them in one go:

```
for k in POSTGRES_PASSWORD KIBAN_DB_PASSWORD KC_DB_PASSWORD KC_BOOTSTRAP_ADMIN_PASSWORD KEYCLOAK_IDENTITY_CLIENT_SECRET \
         KIBAN_REGISTRY_DB_PASSWORD KIBAN_IDENTITY_DB_PASSWORD KIBAN_ORG_DB_PASSWORD \
         KIBAN_AUTHZ_DB_PASSWORD KIBAN_NOTIFICATION_DB_PASSWORD KIBAN_TIMESHEET_DB_PASSWORD \
         KIBAN_DOCS_DB_PASSWORD KIBAN_HELPDESK_DB_PASSWORD KIBAN_NOTIFICATION_WEBHOOK_HMAC_SECRET; do
  sed -i "s|^${k}=\$|${k}=$(openssl rand -hex 24)|" .env
done
```

Note the quickstart's weaker secrets posture: `KC_BOOTSTRAP_ADMIN_PASSWORD` reaches the
`keycloak` and `bootstrap` containers as plain env vars (visible in `docker inspect`), where the
full repo's `infra/compose.yaml` hands it to `bootstrap` as a compose secret file. The identity
service reads its client secret from the file `bootstrap` writes, as in the full stack.

The one-time superadmin password goes in a FILE, never an env var, because the platform never
keeps secrets in env-visible places:

```
mkdir -p secrets-in
openssl rand -base64 24 > secrets-in/superadmin-password
chmod 600 secrets-in/superadmin-password
```

## 3. Up

```
docker compose up -d --wait
```

The first run pulls 8 images (the 5 foundation services plus `migrate`/`bootstrap`/`keycloak`;
the release also publishes `gateway-devcert` and the four sample modules, which this file does
not use) and takes a few minutes depending on your connection. `--wait` blocks until every service reports healthy.

## 4. Log in

Open <http://localhost:3000> (or the `KIBAN_GATEWAY_HTTP_HOST_PORT` you set). Sign in as
`KIBAN_SUPERADMIN_USERNAME` (from `.env`, default `superadmin`) with the password in
`secrets-in/superadmin-password`; that password is temporary, so the first login makes you set
a new one (bootstrap creates the account with Keycloak's `UPDATE_PASSWORD` required action). Port
3000 is the default on purpose: with no `KIBAN_DOMAIN`,
bootstrap registers only fixed dev-loopback redirect URIs (`http://localhost:3000`, `:5173`) on
the realm, so the browser OAuth login only completes from that origin. Remapping the port
breaks the browser login, and there is no other way to get a token: the realm has no
direct-grant client. Use the same host:port every time you sign in: `KEYCLOAK_ISSUER_URL` is compared as a string against the token's `iss` claim.

## Tear down

```
docker compose down          # keeps data
docker compose down -v       # also drops the Postgres volume — full reset
```

## What this is (and isn't)

This is the quickest way to see Kiban running with nothing but Docker. It is **not** a
production setup:
- There is no TLS. The gateway runs its dev-only plain-HTTP listener, since there's no domain to
  issue a real certificate for.
- Postgres is a single node.
- Keycloak's redirect allowlist is fixed to dev-only local origins.

For a real deployment, clone the repository and use the full `infra/compose.yaml`. You can
`make dev` for a local build from source, `make public-up` for a deployment behind a
TLS-terminating reverse proxy, or set `KIBAN_IMAGE_TAG=vX.Y.Z` to deploy from pre-built images.

## Design notes (why this file looks the way it does)

`docker-compose.yml` is GENERATED from the source repo's `infra/compose.yaml` by
`scripts/gen-quickstart-compose.sh` (`make quickstart-compose`; `make docs-freshness-check` fails
when the committed file drifts). Never edit it by hand. `infra/compose.yaml` runs the 5 foundation
services, the `migrate`/`bootstrap` one-shot jobs, a `gateway-devcert` self-signed TLS generator,
the four sample modules behind the `samples` profile, and a custom `keycloak-build` image (Keycloak plus
the Java MFA-setup authenticator and the imported realm). A zero-clone user has no checkout to
build any of those from, so the generator:

- Drops every `build:` and points each `kiban-*` image at
  `ghcr.io/rosschiu/kiban-<service>:${KIBAN_VERSION}`. `migrate`, `bootstrap` and Keycloak
  are pulled from GHCR too (built by `make images-quickstart`, pushed by
  `.github/workflows/release.yml`); `kiban-keycloak` includes the MFA authenticator and realm,
  which a plain `quay.io/keycloak/keycloak` image plus a downloaded realm file would silently drop.
- Drops the profile-gated test fixtures (`mailpit`, `webhook-target`) and `gateway-devcert`,
  and runs the gateway's dev-only plain-HTTP listener instead (`KIBAN_INSECURE_HTTP=true`, host
  port 3000), the same mode `infra/compose.public.yaml` uses behind a real reverse proxy.
  `KEYCLOAK_ISSUER_URL` follows that plain-HTTP origin.
- Takes every env default (ports, names) from `.env.example`; blank fields there become required
  (`${VAR:?}`) in the compose file.
- Inlines `infra/postgres-init/*.sql` as a compose `configs:` entry (no repo file to bind-mount)
  and prefixes the named volumes `kiban-quickstart-` so a `make dev` clone on the same host is
  never touched.

Everything else (env var names, service topology, healthchecks, startup ordering) is
`infra/compose.yaml`'s own service definitions, unchanged.
