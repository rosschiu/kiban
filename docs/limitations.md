# Known limitations (0.1)

Items are grouped by who they affect. Where something is planned, it is planned;
nothing here is promised for a date. The [roadmap](roadmap.md) lists what is planned.

## Security-relevant

- **A passkey policy does not challenge for a passkey at login.** Passkeys can be enrolled and
  required by policy, but the browser login flow accepts a password alone. Authenticator-app
  (TOTP) enforcement works, and a per-user override can only raise the requirement above the
  global policy.
- **No field-level or row-level policy on member data.** Every active member of a company can
  read the directory, including email addresses.
- **Keycloak's own container holds two secrets as environment variables**: its database
  password and its bootstrap admin password. Keycloak reads neither from a file. Every Kiban
  service reads its secrets from files.
- **The org service's internal member-fact reads take no bearer.** Inside the Compose network,
  `GET /internal/org/companies/{id}/members/by-kcsub/{kcSub}` answers any caller; every write
  checks the bearer. Never publish a module container, or any internal service, on a host port.
- **A database restore while gateways keep running.** The gateway remembers, for up to an hour,
  that a user has been provisioned. Restore a database that no longer holds that user and their
  requests fail with `AUTH_USER_NOT_FOUND` until the entry expires or the gateway restarts.

## Identity

- **A service credential is created at bootstrap, not at runtime.** `KIBAN_SERVICE_CLIENTS`
  names the confidential clients; adding one means a restart of the `bootstrap` one-shot. The
  secret is read from the Keycloak admin console; bootstrap neither prints nor rotates it.
- **Companies, org units and members are created by a superadmin.** The routes are on the
  gateway (`/api/org/admin/units`, `/api/org/admin/members`); a company administrator cannot
  create members of their own company yet.
- **A new user has no company until an administrator adds them.** The gateway provisions the
  account on the first request; membership is an explicit administrator action (there is no
  invite flow).
- **The "archived" user state cannot be set.** The lifecycle has the state; no API writes it.
- **Passkey login needs a real hostname.** WebAuthn refuses an IP-literal origin such as
  `https://127.0.0.1:8443`; use a DNS name.
- **A deep link is lost after 30 minutes idle.** A session whose access token has expired but
  whose refresh token is still valid survives a reload and lands where it was; once the refresh
  token has expired too (30 minutes idle), login returns to the application root.

## Deployment

- **Compose is the supported path.** Kubernetes manifests exist, are hardened (non-root, read-only
  filesystems, readiness probes) and were proven on a local kind cluster only. They are not a
  supported production path in 0.1.
- **The gateway does not obtain certificates itself.** Use operator certificates or a
  TLS-terminating proxy in front.
- **`POSTGRES_DB` must be `kiban`** and `POSTGRES_USER` must not be `kiban`: the migrations name
  the database and the owner role, and initialisation refuses other values.
- **Redirect URIs are reconciled at every start.** Bootstrap rewrites the `kiban-frontend`
  client's redirect URIs and web origins on every run to `KIBAN_DOMAIN`'s origin (or the fixed
  localhost set) plus `KIBAN_EXTRA_ORIGINS`. An edit in the Keycloak admin console lasts until
  the next start; put the origin in the variable instead.
- **The audit trail has no API.** Audit rows are read with SQL as the database owner; see
  [Reading the audit trail](operating.md#reading-the-audit-trail).
- **The sample modules' audit tables are not fenced against `TRUNCATE` by the owner role.** The
  foundation audit tables are; the four sample modules' shipped migrations are frozen and get
  the fence with their next migration. Services never connect as the owner.

## Apps and modules

- **An app is enabled for the whole deployment, not per company.** Enabling registers its
  default grants for every active company; there is no per-company switch yet.
- **Checks answer for the bearer only.** An app asks "may this user do this" with the user's own
  token, or "may I" with its service token. There is no way to ask about a third subject, and no
  "list every object this subject may see" API.
- **An app's registration is superadmin work.** Registering and enabling an app, and creating
  companies and members, are superadmin routes; there is no self-service registration.
- **A module is compiled into the platform.** The four sample modules are built by the platform's
  own Dockerfile and need a role migration, a Compose service and a rebuild; an app, by contrast,
  registers at runtime. A module in another language cannot be a module; it is an app.
- **Dependency resolution between modules is declared but not enforced.** The validator checks
  that declared dependencies exist, are acyclic and are marked required; nothing at runtime
  checks that a dependency is enabled before the dependent module is.
- **Entitlement and licensing state exist in the contract but are not enforced.**

## The differential harness

The authorization engine is compared against OpenFGA by a differential harness that runs as
part of `make test`. What it covers: 65 hand-written vectors over the base model (company,
company module, member, position, group and module-object shapes, including
inheritance through positions and groups), two mutation proofs (a position holder change and a
group membership change evaluated identically by both engines), a dedicated cycle proof, and
5000 generated checks over one generated data shape: a module object with a `viewer` relation,
checked for a direct grantee, for a company administrator through inheritance, and for an
administrator of an unrelated company. What it does not cover: relations the vectors do not
name, userset subjects in the generated checks (every generated tuple has a plain user subject),
and anything a module fragment adds beyond the base model. Zero divergences is the pass
condition; it is not a proof of equivalence over the whole model.

## Sample modules

The four sample modules are demonstrations of the contract, not products. These gaps are kept
deliberately:

- **Timesheet.** An approved week can be reopened by adding an entry. `view=all` on the
  submissions list is visible to any member, and a submission is readable by id. Entries can be
  recorded on inactive projects, and a day's total is unbounded. Re-assigning an approver does
  not revoke the previous approver's grants. The sample shell's approvals page can render an
  empty list while the API returns rows.
- **Helpdesk.** A `closed` ticket still accepts comments and reassignment. Agent and approver
  assignment accept member ids from another company (the foreign user still cannot act: every
  decision requires membership). Position- and group-based agent bindings are not reconciled
  when the organization unit is deleted.
- **DocShare.** A share can be revoked while the member is unlinked from a login.
- **Notification.** A subscriber email address is not validated. The webhook target policy
  blocks private and loopback ranges but allows carrier-grade NAT and other special-purpose
  ranges.
- **All four.** Ticket descriptions, document bodies and similar text fields have no size cap
  below the gateway's request limit, and list endpoints return bodies inline. Two concurrent
  requests with the same idempotency key can both be answered `409` instead of one winning.
  Audit rows carry no correlation id and are written for no-op mutations. `/health` is a
  constant `200` (use `/ready` for the database check). The sample OpenAPI files omit some
  status codes the handlers emit.
