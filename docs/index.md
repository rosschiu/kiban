# Why Kiban

Kiban is self-hostable identity, organization and authorization for business applications. It
runs beside your app, in your environment, and answers three questions for every request your
application receives:

- **Who** is this? Login through an embedded identity provider, with your existing corporate
  identity provider federated in. Your backend gets its own credential too.
- **Where** do they sit? A typed organization tree with companies, members, positions and groups.
- **What may they do?** A relationship-based authorization engine in the family of Zanzibar and
  OpenFGA, with position-based and group-based access as first-class features, and an immutable
  audit trail of every change.

Your app keeps its own code, database and deployment. It registers its object types with Kiban,
writes relation tuples on them as things happen, and asks Kiban before it acts. Kiban
deliberately never knows what any of it *means*.

## Start here

- **Deploying Kiban** to try it or run it: [Quickstart](quickstart.md), then [Operating Kiban](operating.md).
- **Integrating your application**, backend and frontend: [Integrate your app](integrate.md).
  Read [Known limitations](limitations.md) first: it says what 0.1 cannot do.
- **The SDKs**: [SDK guide](sdk-guide.md) for TypeScript (browser and Node), with the Python and
  Go clients alongside.
- **The sample modules**, a deeper in-tree integration for contributors: [Building on Kiban](building.md).

## What you get

- A clean Linux host with Docker gets a full stack, a login page and an administrator account
  from one command, in a few minutes.
- Kiban ships its own Keycloak instance inside your deployment. Nothing is hosted by anyone
  else, and there is no runtime dependency on a third-party cloud service.
- Companies, memberships, positions and groups are already modelled. You grant access to a
  *position* ("whoever holds the chair") or a *group*, and access follows assignment and
  membership changes without permission edits.
- Your app registers itself with one manifest: a key, a service client, the feature keys it
  asks about and the object types and relations it owns. No restart, no code in this
  repository, any language.
- SDKs for TypeScript (browser and Node), Python and Go. The browser SDK handles the login flow,
  tokens, typed calls and the error envelope; the backend SDKs handle the service token, user
  token verification, decisions, tuples and member lookups.
- Every write to organization, identity or authorization data records an audit event in the
  same database transaction, into append-only tables, with the actor taken from the verified
  token.

## What Kiban is not

- Not identity-as-a-service. Kiban runs inside your environment; nobody hosts it for you.
- Not multi-tenant SaaS. One deployment serves one tenant, which can contain many companies.
- Not an ERP or an HR system. Organizational *facts* live here; the business logic that uses
  them is your app.
- Not a gateway in front of your app. Your app serves its own API; Kiban only proxies its own.

## Status

Kiban is at version 0.1. It is used by its authors for their own applications first. Checks
answer for the bearer only, there is no "list every object this user may see" API yet,
entitlement and field or row policy are not enforced, and Compose is the only supported
deployment path. The [known limitations](limitations.md) page lists what does not work yet;
read it first.

## Licence

Kiban is licensed under the Apache License, Version 2.0, copyright 2026 Ross Chiu. That is the
same licence as Keycloak, which Kiban embeds, and it covers the whole tree: the foundation, the
SDKs and the sample modules alike. See the repository's `LICENSING.md` for the path map.

## About

Kiban is maintained by Ross Chiu ([@rosschiu](https://github.com/rosschiu)). Security contact:
see [`SECURITY.md`](https://github.com/rosschiu/kiban/blob/main/SECURITY.md) (summarised on the
[Security](security.md) page). Licence:
[`LICENSING.md`](https://github.com/rosschiu/kiban/blob/main/LICENSING.md). Changes are welcome;
the [Contributing](contributing.md) page says how.
