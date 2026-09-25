# Concepts

This page explains the model. The [glossary](glossary.md) defines each term precisely; this page
tells you how they fit together.

## One tenant, many companies

A deployment serves one **tenant**: one organization, one identity realm, one database. Inside
it, the organization tree can hold many **companies**. A company is the anchor for everything
that matters to authorization: membership, module access, and the scope of every decision.

## The organization triangle

Three records describe where a person sits:

- An **org unit** is a node in a typed tree (company, division, team, territory, whatever your
  taxonomy declares). A company is always the top of its tree, and only companies sit at the top.
- A **member** is a person's record inside one company. A member may be linked to a login (a
  user account) or exist without one, for people who never sign in.
- A **position** is a slot on an org unit ("Head of Sales, Region West"). An **assignment** says
  which member holds a position and for which dates. The **holder** is whoever holds it today.

**Groups** are named sets of members inside a company, for access that follows membership
rather than the org chart.

Integrity rules are enforced in the database, not only in application code: a member or position
can never reference another company, a company's id is immutable, and tree moves are serialized.

## Identity

Kiban embeds Keycloak as its OpenID Connect provider. Users log in through it; your existing
identity provider (Entra ID, Okta, Google, any OIDC or SAML provider) is federated into it as a
login source. Kiban never manages your provider's tenant.

Two levels of administration exist:

- The **Superadmin** is the platform-wide operator. There is one seeded at bootstrap. The role
  itself is one tuple, `system:platform#superadmin`, granted and revoked through the platform
  API; its per-module access is a visible, revocable, audited grant rather than a hard-coded
  bypass.
- The **Keycloak Admin** is the identity provider's own master administrator, used only during
  bootstrap and by operators, never at runtime by the application.

Multi-factor policy (authenticator app or passkey) can be required globally or per user; a
per-user override can only raise the requirement.

## Authorization

Access is expressed as **tuples**: `object # relation @ subject`. "Document 42, viewer, user
Alice" or "Company X module helpdesk, editor, position 7 holder". A declarative model says which
relations exist on which object types and how they derive from one another (an editor is also a
viewer, a company-module administrator is an administrator of the module's objects, and so on).

The base model gives every company and every company module a **member** relation: the
company's active, linked members, administrators included. Org writes that tuple when a member
is created or deactivated, so "is an active member" is answered by the same graph as everything
else.

Every request a module handles becomes a **decision**, eight ordered steps: the subject exists;
the login is enabled; the user lifecycle is active; for a global-scope question, the required
platform role is held; for a company-scope question, the company is active, the subject is a
member, not blocked, and holds any required company role; the module is enabled for that
company; the object is bound to that company and the relation holds through the tuple graph;
and, optionally, a business eligibility callback agrees. Any uncertainty (a dependency down, an
unknown relation) is a refusal, never an allow.

The binding step is what keeps one company's objects out of another's reach. Every object type a
module declares carries a `company_module` relation, the **anchor**, and the module writes that
tuple when it creates the object; a check on an object whose anchor names another company is
denied before the relation is even evaluated.

Two grant styles make this practical:

- **Position-based access**: grant a relation to `position:7 # holder`. Whoever holds position 7
  has the access; reassign the position and the access moves. A successor inherits everything
  with zero permission edits.
- **Group-based access**: grant to `group:12 # member`. Every current member has it.

The engine is a Postgres-native subset of the
[Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)
model. The full test suite compares it
against OpenFGA for the relation shapes it supports; the [limitations](limitations.md) page
says exactly what that comparison covers.

## Modules

A **module** is a self-contained package that the platform installs:

| Artifact | What it declares |
|---|---|
| Manifest | key, version, scope (global or per company), service port and health path, database schema |
| Authorization fragment | the module's object types, relations and feature keys, layered on the base model |
| Module OpenAPI | its HTTP API, served under `/api/<module>/…` |
| Migrations | reviewable SQL, applied only to the module's own schema, checksummed |
| Frontend routes | optional; a shell can mount them |

The **registry** keeps the catalog of known modules and their installed and enabled state. The
**gateway** validates the caller's token and forwards `/api/<module>/…` to the module opaquely,
so adding a module requires no gateway change. A module that is not enabled for a company
answers with a clear capability error, never with a silent allow.

A Go module is built on `modulekit`, an Apache-2.0 package with the token verifier, HTTP helpers
and the clients for the authorization, organization and notification services.

## Audit

Every write to organization, identity, authorization or module data records an **audit event**
in the same transaction: who (the actor, taken from the verified token), what (the action), on
which subject, with what payload, and the request's correlation id. Audit tables are append-only
at the database level; the roles services run as cannot update or delete rows.

## The SDK and the shell

The **SDK** is a TypeScript package with no runtime dependencies. It runs the login flow,
refreshes tokens, wraps every call in the platform's success and error envelope, and offers typed
clients and two recipes ("can I do X in company Y?", "share object X with subject Y"). The
**shell** is a sample web application built on the SDK. It shows capability-driven navigation and
hosts module UIs, and it is meant to be forked, not depended on.
