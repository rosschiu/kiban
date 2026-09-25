# Why Kiban

Kiban is a self-hostable foundation for business applications. It answers three questions for
every request your application receives:

- **Who** is this? Login through an embedded identity provider, with your existing corporate
  identity provider federated in.
- **Where** do they sit? A typed organization tree with companies, members, positions and groups.
- **What may they do?** A relationship-based authorization engine, with position-based and
  group-based access as first-class features, and an immutable audit trail of every change.

Kiban deliberately never knows what any of it *means*. Business rules live in modules built on
top, which is why unrelated applications can share the same foundation.

## Start here

- **Deploying Kiban** to try it or run it: [Quickstart](quickstart.md), then [Operating Kiban](operating.md).
- **Integrating an existing application** for login and permissions: [Integrate your app](integrate.md).
  Read [Known limitations](limitations.md) first: it says what 0.1 cannot do.
- **Writing a module** on the foundation: [Building on Kiban](building.md).

## What you get

- A clean Linux host with Docker gets a full stack, a login page and an administrator account
  from one command, in a few minutes.
- Kiban ships its own Keycloak instance inside your deployment. Nothing is hosted by anyone
  else, and there is no runtime dependency on a third-party cloud service.
- Companies, memberships, positions and groups are already modelled. You grant access to a
  *position* ("whoever holds the chair") or a *group*, and access follows assignment and
  membership changes without permission edits.
- A module is a self-contained package: a manifest, an authorization fragment, an OpenAPI
  description, migrations, and optional UI routes. The platform validates, installs, routes to
  and audits it. Four sample modules ship with the repository.
- A TypeScript SDK handles the login flow, tokens, typed API calls and the error envelope. A
  sample web shell shows how to use it and can be forked.
- Every write to organization, identity, authorization or module data records an audit event in
  the same database transaction, into append-only tables, with the actor taken from the verified
  token.

## What Kiban is not

- Not identity-as-a-service. Kiban runs inside your environment; nobody hosts it for you.
- Not multi-tenant SaaS. One deployment serves one tenant, which can contain many companies.
- Not an ERP or an HR system. Organizational *facts* live here; workflows on top of them are
  modules you may or may not install.

## Status

Kiban is at version 0.1. It is used by its authors for their own applications first. Some
capabilities the module contract describes (dependency resolution, entitlement, field and row
policy) are not enforced yet, and Compose is the only supported deployment path. The
[known limitations](limitations.md) page lists what does not work yet; read it first.

## Licence

Kiban is licensed under the Apache License, Version 2.0, copyright 2026 Ross Chiu. That is the
same licence as Keycloak, which Kiban embeds, and it covers the whole tree: the foundation, the
module kit and the sample modules alike. See the repository's `LICENSING.md` for the path map.

## About

Kiban is maintained by Ross Chiu ([@rosschiu](https://github.com/rosschiu)). Security contact:
see [`SECURITY.md`](https://github.com/rosschiu/kiban/blob/main/SECURITY.md) (summarised on the
[Security](security.md) page). Licence:
[`LICENSING.md`](https://github.com/rosschiu/kiban/blob/main/LICENSING.md). Changes are welcome;
the [Contributing](contributing.md) page says how.
