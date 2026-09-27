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

## Apps and modules

An **app** is your application, running beside Kiban. It registers one manifest with a
superadmin call: its key, the service client whose token identifies its backend, the feature
keys it asks about, and an **authorization fragment** declaring its own object types and
relations on top of the base model. From then on the app's backend writes relation tuples on
those types as things happen ("ticket 17 has viewer alice"), asks Kiban before every read and
write, and looks members up. Kiban never proxies the app's own API; the app serves it.

Every object of an app carries a **company anchor**, a tuple binding it to one company, so
every check on it is bound to that company. An app is enabled per deployment and its feature
keys are the vocabulary of its checks: a check naming a feature the manifest does not declare
is refused.

A **module** is the same idea taken further for code that lives in this repository: a manifest,
a fragment, an OpenAPI file, checksummed migrations and optional UI routes, built and routed by
the platform itself. The four sample modules are worked examples of that deeper integration and
are off by default; the **registry** keeps the catalog of apps and modules and their installed
and enabled state.

## Audit

Every write to organization, identity, authorization or module data records an **audit event**
in the same transaction: who (the actor, taken from the verified token), what (the action), on
which subject, with what payload, and the request's correlation id. Audit tables are append-only
at the database level; the roles services run as cannot update or delete rows.

## The SDKs and the shell

The **browser SDK** (`@rosschiu/kiban-sdk`, TypeScript, no runtime dependencies) runs the login
flow, refreshes tokens, wraps every call in the platform's success and error envelope, and
offers typed clients and recipes. The **backend SDKs** (`@rosschiu/kiban-sdk/server` for Node,
`kiban-sdk` for Python, `github.com/rosschiu/kiban/sdk` for Go) do the same five things each:
obtain the app's service token, verify a user's token, ask for decisions, write and remove
tuples on the app's own types, look members up. The **shell** is a sample web application built
on the browser SDK; it is meant to be forked, not depended on.
