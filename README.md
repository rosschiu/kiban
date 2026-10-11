# Kiban - Permission control for organization

[![CI](https://github.com/rosschiu/kiban/actions/workflows/ci.yml/badge.svg)](https://github.com/rosschiu/kiban/actions/workflows/ci.yml)

Self-hostable identity, organization and authorization for business applications. Kiban answers three questions:
- **who**: user's identity
- **where**: user's position in a hierarchy (companies, members, positions, groups)
- **what may they do**: (relationship-based authorization engine with an immutable audit trail).

This project is an extract of past enterprise projects with features revamp and enhancements.

**Documentation: <https://rosschiu.github.io/kiban/>**
[Quickstart](https://rosschiu.github.io/kiban/quickstart/)
[Integrate your app](https://rosschiu.github.io/kiban/integrate/) for the backend and frontend steps
[Known limitations](https://rosschiu.github.io/kiban/limitations/)

## Features

- **Identity**: an embedded Keycloak instance (OpenID Connect with PKCE; authenticator-app or
  passkey MFA policy, global or per user, where a per-user override can only raise it) synced to
  a Postgres identity store; a user is provisioned on their first request. Your existing identity
  provider federates in as a login source. A backend gets its own credential: a confidential
  service client whose token the gateway accepts.
- **Organization**: a typed org-unit tree, members, positions and groups, with the company as the
  sole authorization anchor. Integrity is enforced in the database: cross-company facts are
  unrepresentable, concurrent tree writes are serialized, a company's id is immutable.
- **Authorization**: a Postgres-native
  [Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)-subset
  engine (relation tuples plus a declarative model), compared against OpenFGA in the test suite.
  Your app registers its own object types and relations on top of the base model, writes
  tuples on them, and asks for decisions. Every object check is bound to the request's company;
  the superadmin role is one revocable tuple.
- **Position-based and group-based access**: grant to a position and whoever holds it has the
  access; grant to a group and every current member has it. Reassignments and membership changes
  need no permission edits.
- **Audit**: every mutation writes its audit event in the same transaction into append-only
  tables, with the actor taken from the verified token and the request's correlation id.
- **SDKs**: TypeScript for the browser (login, session, typed calls) and for Node backends,
  Python and Go for backends. Each backend SDK does the same five things: obtain the app's
  service token, verify a user's token, ask for decisions, write and remove tuples on the app's
  own types, look members up.

Four sample modules ship in the repository as worked examples of a deeper integration
(`notification`, `docs`, `helpdesk`, `timesheet`); they are off by default.


## Quickstart

Needs `docker` (with the Compose plugin), `make` and `openssl` on a Linux x86_64 host. Every service builds
inside containers.

```
make setup   # checks docker, writes .env with generated secrets (once), creates infra/secrets-in/
make dev     # builds and starts every container, waits until all are healthy
```

Then access Kiban at `https://127.0.0.1:8443` (self-signed certificate). Log in as
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
make check           # format, vet, vulnerability check, unit tests, module and migration validation, web checks, coverage ratchet (40 scopes; this run includes the live-tagged tests), licence and secret scans
make test            # Go tests under the race detector, and the OpenFGA differential harness
```

Coverage is enforced by a per-package ratchet whose minimums only rise. Browser end-to-end tests
(Playwright) target the isolated stack only; a guard refuses to run them against a live
deployment. See `CONTRIBUTING.md`.

## Operating

Every foundation service and module exposes Prometheus metrics on its internal listener; the
gateway has no bare `/metrics` and serves the whole platform's exposition (its own included) at
`GET /api/platform/metrics` for a superadmin bearer. Upgrades, backup and restore, TLS
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
