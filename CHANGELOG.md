# Changelog

One line per change. Versions follow [Semantic Versioning](https://semver.org/); the current version is in [`VERSION`](VERSION).

## [Unreleased]

- Compose marks Keycloak healthy only on a `200` readiness status, not on any `"status": "UP"` fragment; bootstrap's readiness wait grows from 30s to 90s, so a cold first `docker compose up --wait` no longer fails
- Authz debug check answers an engine refusal as `422` `VALIDATION_FAILED` (was the `VALIDATION_ERROR` shape code)
- Quickstart "What to try first" points at the admin routes instead of a removed section
- The discovery document's `issuer` equals the `iss` every token carries (`<origin>/realms/<realm>`) at both `/auth/realms/…` and `/realms/…`, so a standard OpenID Connect library accepts Kiban's tokens; the `/realms/` mount forwards Keycloak untouched, so a login started there completes
- Zero-clone quickstart serves a real origin: `deploy/quickstart/compose.public.yaml` (generated from the source overlay) sets the public issuer, Keycloak hostname, `KIBAN_DOMAIN` and `KIBAN_TRUSTED_PROXY` from one `KIBAN_PUBLIC_HOST`
- Second-factor policy through the gateway: `GET`/`PUT /api/platform/admin/mfa-policy/global`, `GET`/`PUT`/`DELETE .../users/{subject}`, `POST .../sync` (superadmin); documented on the Operating page, with the note that a new realm requires no second factor

## [0.1.0] — 2026-09-25

First public release, Apache-2.0. Kiban runs beside your app: the app registers its model and
serves its own API; the sample modules are examples, off by default.

- Backend SDKs: `@rosschiu/kiban-sdk/server` (Node), `kiban-sdk` (Python), `github.com/rosschiu/kiban/sdk` (Go): service token, user token verification, decisions, tuples, member lookup, app registration
- Kiban repositioned as a service beside your app (OpenFGA-style): the app registers its model and serves its own API; the module runtime is the sample modules' in-tree path
- `KIBAN_EXTRA_ORIGINS`: extra web origins and native (custom-scheme) redirect URIs for `kiban-frontend`, also on the gateway's CORS allow-list; a Flutter or second web app can log in
- Apps register at runtime (`POST /api/platform/admin/apps`, manifest with fragment, features and service client); an app's backend writes tuples on its own types and looks up members; a check names only a feature its module declares (one string, one feature)
- Company, org-unit and member administration through the gateway (`/api/org/admin/units`, `/api/org/admin/members`)
- The four sample modules are optional: `COMPOSE_PROFILES=samples` and `KIBAN_INSTALLED_MODULES` bring them up; the default stack is the foundation only and the gateway no longer waits on them
- Service credential: `KIBAN_SERVICE_CLIENTS` creates confidential Keycloak clients whose client-credentials tokens the gateway accepts, for workers and connectors
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
