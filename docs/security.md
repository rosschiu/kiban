# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the `rosschiu/kiban` repository ("Security"
tab, "Report a vulnerability"). Do not post details in a public issue. If the button is not
available, open an issue that says only that you need a private channel; a maintainer will
arrange one.

Include the affected version or commit (`kiban_build_info{version,commit}` on every service), a
reproduction, and the impact you believe it has.

## What the platform guarantees

### Authorization

Authorization fails closed: any error while evaluating a decision is a refusal. Every object
check is bound to the request's company: companies and company modules by id, positions and
groups through their company, module objects through the anchor tuple their module writes at
creation. An object from another company is denied.

A grant names the company, may only write tuples on the calling module's own object types, and
needs the caller to pass that module's company-scope decision; module-tier tuples additionally
need the company-module administrator relation. Base-model tuples cannot be written through the
grants API.

The superadmin role is a single authorization tuple. Grant and revoke are immediate and audited,
and the last superadmin cannot be revoked.

The authorization engine is compared against OpenFGA in `make test` (65 vectors, two mutation
proofs, a cycle proof, 5000 generated checks). The limitations page says what that does not
cover.

### Identity and audit

The actor of every request is the verified bearer token; client-supplied identity headers are
rejected.

Every mutation is audited in the same transaction, with the actor taken from the verified token
(never from the request body) and the request's correlation id. A definite denial on an
administrative route is audited with its reason. Foundation audit tables refuse updates, deletes
and `TRUNCATE` at the database level, and the service roles have no privilege to bypass that.

Authenticator-app or passkey MFA policy is set globally or per user; a per-user override can only
raise the requirement. Passkey enrolment works; the login challenge for a passkey policy does not
yet (see limitations).

Bootstrap enforces brute-force protection (temporary lockout after ten failures) and the
password policy `length(12) and notUsername and notEmail`. The realm binds one browser flow
(`kiban browser`): password form, conditional one-time code, then Kiban's MFA-setup
authenticator as a required step, so every interactive login passes through it. There is no
direct-grant or client-credentials client that issues a Kiban token (see limitations).

### Deployment

Every service connects to the database with its own role, limited to its own schema. `kiban` is
the non-superuser owner of the application database and runs migrations and bootstrap;
`keycloak` owns Keycloak's database; the superuser (`POSTGRES_USER`, default `postgres`) is used
only at initialisation.

The superadmin's initial password, the identity client secret and the Keycloak admin password
reach Kiban's services as mounted files (`_FILE` variables), never as process environment. See
the limitations page for Keycloak's own container.

Gateway responses carry `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and (over
TLS) `Strict-Transport-Security`; the shell is served with an enforced Content-Security-Policy.
Over-limit bodies are refused. The Keycloak admin console and the master realm are not reachable
through the gateway.

Application containers run as uid 65532 with a read-only root filesystem, all capabilities
dropped and no privilege escalation, in Compose and in the Kubernetes template.

There is no runtime dependency on any third-party service. TLS is either operator certificates on
the gateway or your own TLS-terminating reverse proxy in front of it; the gateway never contacts
a certificate authority.

Secret scanning, dependency licence scanning and vulnerability checks run in `make check`.

## Known gaps

See [known limitations](limitations.md). Items there that touch security are listed first.
