# Changelog

One line per change. Versions follow [Semantic Versioning](https://semver.org/); the current version is in [`VERSION`](VERSION).

## [Unreleased]

- The four sample modules are optional: `COMPOSE_PROFILES=samples` and `KIBAN_INSTALLED_MODULES` bring them up; the default stack is the foundation only and the gateway no longer waits on them
- Service credential: `KIBAN_SERVICE_CLIENTS` creates confidential Keycloak clients whose client-credentials tokens the gateway accepts, for workers and connectors
- Roadmap and Changelog pages on the documentation site; the site deploys on every push to main

## [0.1.0] — 2026-09-25

First public release, Apache-2.0.

- Identity: embedded Keycloak, OpenID Connect with PKCE, MFA policy (authenticator app or passkey), bootstrap seeds the superadmin with a file-delivered password
- Organization: org-unit tree, members, positions and groups; company is the sole authorization anchor; cross-company facts are unrepresentable
- Authorization: Postgres-native Zanzibar-subset engine, differential-tested against OpenFGA; modules ship an authorization fragment
- Position- and group-based access: rights follow the position holder or group membership with zero permission edits
- Audit: every mutation writes an append-only audit row in the same transaction
- Module runtime: manifest, fragment, OpenAPI file, checksummed migrations; validated by `make validate-modules`, routed by a version-blind gateway
- Gateway: single origin, bearer-only `/api/*`, CORS, security headers, request limits, `/ready` health
- Sample modules: notification, docs (DocShare), helpdesk, timesheet
- SDK `@rosschiu/kiban-sdk`: session with PKCE and refresh, API client, org and effective-access clients, `canI` and grant recipes
- Sample shell: React, CSP enforced, company switcher, administration pages
- Platform role is one tuple (`system:platform#superadmin`) with grant and revoke routes
- `GET /api/platform/metrics` aggregates every service's metrics for one scrape target
- Postgres roles: non-superuser owner `kiban`, per-service roles, secrets read from files
- Containers run as uid 65532, read-only root, no capabilities; base images digest-pinned
- Compose is the supported deployment; Kubernetes manifests proven on kind only
- Coverage ratchet, OpenAPI response validation, licence and secret scans in `make check`
- Documentation site: quickstart, integrate, concepts, building, SDK guide, operating, security, limitations

[Unreleased]: https://github.com/rosschiu/kiban/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rosschiu/kiban/releases/tag/v0.1.0
