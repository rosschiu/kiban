# Quickstart

Two paths. The first needs a checkout of the repository and builds everything locally. The second
pulls published images and needs no checkout.

## Requirements

- Linux on x86_64 (what the project builds and tests on; other platforms are untested).
- Docker Engine with the Compose plugin. The project is tested against Docker 29 and Compose v5.
- `make` for the checkout path.
- Roughly 4 GB of RAM and 2 CPU cores as a practical floor, and 10 GB of free disk. The idle
  stack uses about 1.2 GB, most of it Keycloak.

## Path A: from a checkout

```
git clone https://github.com/rosschiu/kiban.git
cd kiban
make setup   # checks docker, writes .env with generated secrets (once), creates infra/secrets-in/
make dev     # builds and starts every container, waits until all are healthy
```

`make dev` ends by printing the container list. "Healthy" means every service answered `/ready`,
so its database connection is up too. Kiban is then at `https://127.0.0.1:8443` with a
self-signed certificate, so expect a browser warning. Plain HTTP is on `http://127.0.0.1:8090`.

Log in as the user named by `KIBAN_SUPERADMIN_USERNAME` in `.env` (default `superadmin`),
with the password in `infra/secrets-in/superadmin-password`. That file is generated once with
mode 0600 and is never printed to a log. The password is temporary: the first login makes you
set a new one (12 characters minimum, not the username or email).

To stop: `make dev-down` keeps your data, `make dev-clean` removes the volumes as well.

## Path B: published images, no checkout

Download two files, set your secrets, start.

```
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/rosschiu/kiban/main/deploy/quickstart/docker-compose.yml
curl -fsSL -o .env.example       https://raw.githubusercontent.com/rosschiu/kiban/main/deploy/quickstart/.env.example
cp .env.example .env
```

Every secret in `.env` is blank on purpose. Fill them in one shot:

```
for k in POSTGRES_PASSWORD KIBAN_DB_PASSWORD KC_DB_PASSWORD KC_BOOTSTRAP_ADMIN_PASSWORD KEYCLOAK_IDENTITY_CLIENT_SECRET \
         KIBAN_REGISTRY_DB_PASSWORD KIBAN_IDENTITY_DB_PASSWORD KIBAN_ORG_DB_PASSWORD \
         KIBAN_AUTHZ_DB_PASSWORD KIBAN_NOTIFICATION_DB_PASSWORD KIBAN_TIMESHEET_DB_PASSWORD \
         KIBAN_DOCS_DB_PASSWORD KIBAN_HELPDESK_DB_PASSWORD KIBAN_NOTIFICATION_WEBHOOK_HMAC_SECRET; do
  sed -i "s|^${k}=\$|${k}=$(openssl rand -hex 24)|" .env
done
mkdir -p secrets-in && openssl rand -base64 24 > secrets-in/superadmin-password && chmod 600 secrets-in/superadmin-password
docker compose up -d --wait
```

Open `http://localhost:3000` (use `localhost`, not `127.0.0.1`: the realm's login redirect is
registered for `http://localhost:3000`) and log in as the superadmin with the password from
`secrets-in/superadmin-password`; the first login makes you set a new one. Path B pulls the
released images from GHCR; set `KIBAN_VERSION` in `.env` to choose the image tag.

## What to try first

A fresh stack has no company, and the gateway has no route that creates one: companies, org
units and members are written through the org service's internal routes, from inside the
Compose network. The administration pages cover positions and groups.

1. Create the first company and make yourself its first member with the commands in
   [Integrate your app](integrate.md#escape-hatch-create-a-company-and-its-first-member).
2. Open the administration pages, create a position in that company and assign your member to
   it.
3. Bring up a sample module (`COMPOSE_PROFILES=samples` and `KIBAN_INSTALLED_MODULES` in
   `.env`, then `make dev` again), enable it for the company, and grant it to the position
   rather than to the person.
4. Change the position holder and watch access move with the chair.

## Next

- [Concepts](concepts.md) explains the model you just touched.
- [Integrate your app](integrate.md) connects an existing frontend or backend to this stack.
- [Operating Kiban](operating.md) covers TLS, identity federation, backup and upgrade.
- [Building on Kiban](building.md) is for module and application developers.
