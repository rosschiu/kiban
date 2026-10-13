# Changelog

One line per change. Versions follow [Semantic Versioning](https://semver.org/); the current version is in [`VERSION`](VERSION).

## [Unreleased]

- Docs: only decisions are revocation-aware; a verified token alone serves a disabled user until it expires, so the integrate page, the limitations page and the three SDKs' token-verify docs say to make a decision before serving data

## [0.1.2] — 2026-10-12
Fixes from the first two teams on 0.1.1: the Kubernetes Secret namespace, `batch-can` object
fields, registration of a fragment without the company anchor and the grants rule for other apps'
types; plus trusted publishing, the release gate off the advisory feed, and the glue scripts
reduced to one Go tool.

- Kubernetes: the overlays set `namespace: kiban`, the generated and example Secrets carry it, and `make k8s-check` fails on any rendered resource outside it; in 0.1.1 the Secret moved to the overlay without a namespace, landed in the kubeconfig's current one, and every pod waited on it
- `batch-can` echoes each result's `object` as `{type, id}` again; 0.1.1 wrote the Go field names `Type`/`ID`, so the Node and Python SDKs returned an empty object on every row (decisions were right; the Go SDK was unaffected because its decoder matches field names case-insensitively); the OpenAPI object reference is now exactly `{type, id}` and the live OpenAPI run validates it
- App registration refuses a fragment whose object type lacks the `company_module` anchor with `422`, nothing stored; before, it registered and every authorization check for every module failed once the app was enabled, because authz validates the anchor only when it loads the fragment
- Grants: an app's service account that is a member of a company can no longer write tuples on another app's object types there; a non-owner app needs the company's `admin` relation (`403 COMPANY_ROLE_REQUIRED` otherwise), the superadmin exception and the owning app's own types are unchanged
- Release gate no longer runs the advisory scan at the tag (`make check VULNCHECK=0`); `govulncheck` stays on every PR and runs weekly (`vulncheck.yml`), opening a `security` issue on a finding, so a release never races the advisory feed
- API docs pages load Redoc from Redocly's CDN through one pinned, integrity-checked `<script>` instead of inlining the bundle into `docs/api/*.html`; the backend SDK trims the gateway origin's trailing slashes without a regex; the remaining code-scanning alerts were triaged with a written reason each
- SDKs publish to npm and PyPI by trusted publishing (OIDC from `release.yml`); the `NPM_TOKEN` and `PYPI_APIKEY` secrets are no longer read and can be deleted once the publishers are registered on npmjs.com and pypi.org
- The nine manual proof scripts (`infra/e2e-*.sh`, `modules/*/curl-proof.sh`, the restart-survival proof, org's `smoke.sh`) are removed; the `-tags live` Go tests and the Playwright suites cover those journeys in the gate. The Python SDK's build output is no longer tracked
- One developer tool, `go run ./tools/dev <subcommand>`, replaces the five gate and generator scripts (`coverage-gate.sh`, `kustomize-check.sh`, `license-scan.sh`, `pin-images.sh`, `gen-quickstart-compose.sh`), `build-api-docs.mjs`, `cmd/modvalidate` and the three `tools/*/cmd` binaries; every `make` target is one line and nothing is CI-only
- No shell in the images: the migrate job and bootstrap set database role passwords over the wire (`go run ./tools/dev migrate`, `internal/dbrole`), the gateway generates its own self-signed development certificate (`KIBAN_TLS_SELF_SIGNED_DIR`; no `gateway-devcert` image, 12 images), the two Postgres init scripts are one, and `deploy/k8s/kiban.sh secrets|apply` replaces `gen-secrets.sh` and `apply.sh`

## [0.1.1] — 2026-10-08

From two integration reviews: a public origin and a standard OIDC issuer for the published
images, second-factor policy and company administrators through the gateway, service accounts
as members, org reads and SDK parity, and package publishing.

- Go 1.26.9 toolchain and builder image (ten standard-library advisories in `net/http`, `net/textproto` and `crypto/tls`, GO-2026-6603 to GO-2026-6617); the release gate's `govulncheck` blocked the tag on 1.26.8
- `golang.org/x/text` 0.41.0 (GO-2026-6629, a panic on crafted input in the `precis` package that `pgx` reaches on connect); the release gate's `govulncheck` blocked the 0.1.1 tag on 0.40.0
- Compose marks Keycloak healthy only on a `200` readiness status, not on any `"status": "UP"` fragment; bootstrap's readiness wait grows from 30s to 90s, so a cold first `docker compose up --wait` no longer fails
- Authz debug check answers an engine refusal as `422` `VALIDATION_FAILED` (was the `VALIDATION_ERROR` shape code)
- Quickstart "What to try first" points at the admin routes instead of a removed section
- The discovery document's `issuer` equals the `iss` every token carries (`<origin>/realms/<realm>`) at both `/auth/realms/…` and `/realms/…`, so a standard OpenID Connect library accepts Kiban's tokens; the `/realms/` mount forwards Keycloak untouched, so a login started there completes
- An object carries one company anchor: the grants route refuses a second anchor with `422` and migration `authz/0012` adds the unique index behind it; a repeated tuple is still a no-op; the grant ledger records changes only (a duplicate grant or a revoke of a missing tuple no longer writes a phantom row)
- Kubernetes: `apply.sh` waits only for the Deployments the overlay created, so a core-only apply no longer fails on the absent sample modules; the gateway receives `KIBAN_DOMAIN` and `KIBAN_EXTRA_ORIGINS` from `kiban-config`, as bootstrap already did
- The Kustomize base carries no Secret, so it works as a remote base from another repository; each overlay supplies `kiban-secrets` (`gen-secrets.sh <overlay>` writes it there and moves a 0.1.0 `base/secret.yaml` into place); `make k8s-check` renders base and overlays without a cluster
- Zero-clone quickstart serves a real origin: `deploy/quickstart/compose.public.yaml` (generated from the source overlay) sets the public issuer, Keycloak hostname, `KIBAN_DOMAIN` and `KIBAN_TRUSTED_PROXY` from one `KIBAN_PUBLIC_HOST`
- Second-factor policy through the gateway: `GET`/`PUT /api/platform/admin/mfa-policy/global`, `GET`/`PUT`/`DELETE .../users/{subject}`, `POST .../sync` (superadmin); documented on the Operating page, with the note that a new realm requires no second factor
- Members carry `kind` (`person` or `service`): identity records whether a user is a client's service account (confirmed through Keycloak's client link at provisioning), and the member directory and admin member routes return it; bootstrap grants identity's service account the read-only `view-clients` role for that check and repairs it on an existing realm
- Docs: an app's service account is a user; to run background jobs in a company it must be made a member of that company (the two admin calls), while writing tuples on the app's own types needs no membership
- A company's administrator (`company:<id>#admin`) manages that company's members, positions, assignments and groups through `/api/org/admin/*`; the gateway and org both decide "superadmin, or administrator of this company"; companies and org units stay superadmin work
- Two company reads for apps and members: a position's holder on a date (`GET /api/org/companies/{id}/positions/{positionId}/holder?date=`) and a group's members, for any active member of the company or a superadmin, never across companies
- SDK parity: batch checks, companies the user may see, member directory, position holder and group members in the Go, Node (`server`) and Python SDKs; Python gains `batch_can`
- Each sample module has its own Compose profile beside `samples`: `COMPOSE_PROFILES=docs` starts one container, not four
- Releases publish `kiban-sdk` to PyPI and `@rossbsol/kiban-sdk` to the public npm registry when the repository holds `PYPI_APIKEY` and `NPM_TOKEN`; both packages are also attached to the workflow run as artifacts. The npm package is renamed from `@rosschiu/kiban-sdk` (never published publicly) and GitHub Packages is no longer used

## [0.1.0] — 2026-09-25

First public release, Apache-2.0. Kiban runs beside your app: the app registers its model and
serves its own API; the sample modules are examples, off by default.

- Backend SDKs: `@rossbsol/kiban-sdk/server` (Node), `kiban-sdk` (Python), `github.com/rosschiu/kiban/sdk` (Go): service token, user token verification, decisions, tuples, member lookup, app registration
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
- Gateway: single origin, bearer-only `/api/*`, CORS, security headers, request limits; every service behind it answers `/ready`
- Sample modules: notification, docs (DocShare), helpdesk, timesheet
- SDK `@rossbsol/kiban-sdk`: session with PKCE and refresh, API client, org and effective-access clients, `canI` and grant recipes
- Sample shell: React, CSP enforced, company switcher, administration pages
- Platform role is one tuple (`system:platform#superadmin`) with grant and revoke routes
- `GET /api/platform/metrics` aggregates every service's metrics for one scrape target
- Postgres roles: non-superuser owner `kiban`, per-service roles; the superadmin password, identity client secret and Keycloak admin password read from files
- Containers run as uid 65532, read-only root, no capabilities; base images digest-pinned
- Compose is the supported deployment; Kubernetes manifests proven on kind only
- Coverage ratchet, OpenAPI response validation, licence and secret scans in `make check`
- Documentation site: quickstart, integrate, concepts, building, SDK guide, operating, security, limitations

[Unreleased]: https://github.com/rosschiu/kiban/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/rosschiu/kiban/releases/tag/v0.1.2
[0.1.1]: https://github.com/rosschiu/kiban/releases/tag/v0.1.1
[0.1.0]: https://github.com/rosschiu/kiban/releases/tag/v0.1.0
