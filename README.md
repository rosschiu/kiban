# Kiban (基盤)

[![CI](https://github.com/rosschiu/kiban/actions/workflows/ci.yml/badge.svg)](https://github.com/rosschiu/kiban/actions/workflows/ci.yml)

Self-hostable foundation for business applications: an **organizational identity and access
substrate**. Kiban knows *who* someone is, *where* they sit in an organization, and *what they
may do*, and deliberately never what any of it means. Business meaning lives in modules built on
top.

**Documentation: <https://rosschiu.github.io/kiban/>** (source in `docs/`; `make docs-site`
builds it locally). Start with the [quickstart](https://rosschiu.github.io/kiban/quickstart/) to
run it, [Integrate your app](https://rosschiu.github.io/kiban/integrate/) to add login and
permissions to an existing application, and
[known limitations](https://rosschiu.github.io/kiban/limitations/) for what 0.1 cannot do.
`AGENTS.md` gives a coding agent the same reading order and the rules of the tree.

## What it does

- **Identity**: an embedded Keycloak instance (OpenID Connect with PKCE; authenticator-app or
  passkey MFA policy, global or per user, where a per-user override can only raise it) synced to
  a Postgres identity store; a user is provisioned on their first request. Your existing identity
  provider federates in as a login source.
- **Organization**: a typed org-unit tree, members, positions and groups, with the company as the
  sole authorization anchor. Integrity is enforced in the database: cross-company facts are
  unrepresentable, concurrent tree writes are serialized, a company's id is immutable.
- **Authorization**: a Postgres-native
  [Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)-subset
  engine (relation tuples plus a declarative model), compared against OpenFGA in the test suite. Every object check is bound to the request's
  company; the superadmin role is one revocable tuple. Modules ship an authorization fragment
  layered on the base model; a disabled module's fragment is inert.
- **Position-based and group-based access**: grant to a position and whoever holds it has the
  access; grant to a group and every current member has it. Reassignments and membership changes
  need no permission edits.
- **Audit**: every mutation writes its audit event in the same transaction into append-only
  tables, with the actor taken from the verified token and the request's correlation id.
- **Module runtime**: a module is a self-contained contract (manifest, authorization fragment,
  OpenAPI file, checksummed migrations, optional UI routes) validated by `make validate-modules`,
  installed by the registry, routed by a version-blind gateway, and surfaced by an SDK-driven
  sample shell. Go modules build on `modulekit` (Apache-2.0); frontends on the TypeScript SDK.

Four sample modules ship in the repository: `notification`, `docs` (DocShare: shared files with
per-file sharing as live authorization tuples), `helpdesk`, and `timesheet`.

**Stack**: Go (standard library `net/http`), Postgres 18, Keycloak 26, a TypeScript SDK and a
React sample shell (npm workspaces), Docker Compose. Kubernetes manifests exist under
`deploy/k8s/` and are proven on a local kind cluster only.

## Quickstart

Needs `docker` (with the Compose plugin) and `make` on a Linux x86_64 host. Every service builds
inside containers.

```
make setup   # checks docker, writes .env with generated secrets (once), creates infra/secrets-in/
make dev     # builds and starts every container, waits until all are healthy
```

Kiban is then at `https://127.0.0.1:8443` (self-signed certificate). Log in as
`KIBAN_SUPERADMIN_USERNAME` from `.env` (default `superadmin`) with the password in
`infra/secrets-in/superadmin-password` (a 0600 file written once, never printed to a log; the
first login makes you change it). `make dev-down` stops it and keeps data; `make dev-clean` also
removes the volumes.

A checkout-free variant lives in `deploy/quickstart/`: it pulls the foundation images only
(no `gateway-devcert`, no sample modules).

## Requirements

- Linux, x86_64 (what the project builds and tests on).
- Docker Engine 29 and Compose v5 or newer.
- About 4 GB RAM and 2 cores as a practical floor (the idle stack uses about 1.2 GB, mostly
  Keycloak); 10 GB free disk for images, volumes and data growth.

## Development

```
make test-stack-up   # isolated test stack (compose project kiban-test, its own ports and volumes)
make check           # format, vet, vulnerability check, unit tests, module and migration validation, web checks, coverage ratchet (40 scopes), licence and secret scans
make test            # full tests, including live-tagged tests and the OpenFGA differential harness
```

Coverage is enforced by a per-package ratchet whose minimums only rise. Browser end-to-end tests
(Playwright) target the isolated stack only; a guard refuses to run them against a live
deployment. See `CONTRIBUTING.md`.

## Operating

Every service exposes Prometheus metrics on its internal listener; the gateway also serves its
own at `GET /api/platform/metrics` for a superadmin bearer. Upgrades, backup and restore, TLS
modes and identity federation are covered in the documentation's *Operating Kiban* page.

## Status and limitations

Version 0.1. Read the documentation's *Known limitations* page before relying on anything; it
lists what is not built or not yet right.

## Licence

Apache-2.0, copyright 2026 Ross Chiu, for the whole tree: foundation, sample modules, module
kit, SDK and documentation. See `LICENSING.md` for the path map and `SECURITY.md` for reporting
vulnerabilities.

## Maintainer

Kiban is maintained by Ross Chiu ([@rosschiu](https://github.com/rosschiu)). Security contact:
see `SECURITY.md`. Licence: `LICENSING.md`.
