# Roadmap

What is planned for Kiban after 0.1. Items are grouped by who they help. Nothing here is
promised for a date; each ships when it is done and appears in the [changelog](changelog.md).
The [known limitations](limitations.md) page describes what 0.1 does today.

## Integrating from any backend

- **A service-to-service credential.** A confidential Keycloak client with a service account and
  the `kiban-api` audience, authorized per caller. A Node.js, Python or Go backend will then call
  Kiban on its own behalf instead of only forwarding a user's bearer token.
- **Company, org unit and member creation through the gateway**, plus an invite flow, so the
  first company no longer needs a call from inside the Compose network.
- **Published OpenAPI files with security schemes**, so generated clients in any language attach
  the bearer without hand-patching.
- **A REST-only integration guide** for backends without an SDK.

## Web and mobile frontends

- **Extra origins and redirect URIs by configuration.** A variable that adds origins, including
  custom URI schemes, to the `kiban-frontend` client instead of bootstrap rewriting the list to a
  single domain on every start. This is what a Flutter or other native app needs to log in.
- **A native login guide** with the OpenID Connect settings for AppAuth-style libraries, and a
  refresh-token policy suited to mobile sessions.

## Modules

- **Runtime module install from a manifest.** Register and install a module without editing Go,
  including catalog entry, fragment load, database role provisioning and retirement. This is the
  first step toward modules written outside this repository or in other languages.
- **Runtime dependency resolution** between modules, so a dependent module cannot be enabled
  before its dependency.
- **One error code when a foundation service is unavailable**, and a single ordering for
  grant-then-index writes, across the sample modules.
- **Upstream `401` passed through** by modulekit instead of becoming `503`, so an SDK client's
  refresh-and-retry works against module routes.

## Operating

- **An audit trail API**, so audit rows no longer need SQL access as the database owner.
- **`KIBAN_DOMAIN` passed to the gateway in the public Compose file**, so public-mode CORS uses the
  deployment's domain.
- **Kubernetes as a supported path.** The manifests exist and are proven on kind only.

## Security

- **Passkey challenge at login** when the policy requires a passkey.
- **Field- and row-level policy on member data**, so the directory is not readable in full by
  every member.
- **A writer for the `archived` user state.**
- **A wider differential harness** covering userset subjects and module fragment relations, and
  the concurrent batch check on the request path.

## Later

Commercial module packaging and entitlement enforcement, identity-provider federation beyond
plain OpenID Connect (Entra ID, SCIM, account linking), an all-in-one image, and the
administration consoles for authorization, audit and users.
