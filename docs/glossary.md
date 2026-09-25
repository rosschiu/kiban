# Glossary

One canonical term per concept. Documentation, API fields, code identifiers and comments use
these words. The "Instead of" column lists words you may still meet in older material; the code
anchor is the identifier that fixes the meaning.

## Identities and actors

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Keycloak user | The account in the embedded identity provider, identified by its OIDC `sub`. | `kc_sub` | |
| User account | Kiban's own record for a Keycloak user, keyed by that `sub`. Created by bootstrap for the superadmin and by identity's resolve endpoint. | `identity.user_account` | |
| Member | A person's record inside one company; may or may not be linked to a user account. | `org.member` | staff |
| Subject | The identity an authorization question is about: `user:<sub>` in tuples. On the wire it is `subjectId`, which carries the Keycloak `sub`, not the user-account id. | `decision.Request.SubjectID` | authUserId |
| Actor | The subject that performed an audited action, always derived server-side from the verified token. | `audit.Event.Actor` | |
| Resolve | Identity's create-or-fetch of a user account from a token. Only this meaning; say "dependency resolution" or "module lookup" for anything else. | `POST /internal/identity/resolve` | |

## Privilege levels

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Superadmin | The platform-wide operator role. Its one record is the tuple `system:platform#superadmin @ user:<sub>`, granted and revoked through `/api/platform/admin/platform-roles`. | role `kiban-superadmin`, guard `RequireSuperadmin`, SDK `createSuperadminClient` | platform admin |
| Company Superadmin | Full administrative access over one module within one company. There is no company-wide relation yet. | relation `company_module#admin` | company admin, module admin |
| Keycloak Admin | The identity provider's master administrator, used by bootstrap and operators only, never at runtime. | `KC_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | master admin |
| Demo Superadmin | The superadmin account of the public demo (`admin` / `DemoAdmin!2026`). | `KIBAN_DEMO_ADMIN_PASSWORD` | demo admin |
| Superuser | The Postgres cluster superuser (`POSTGRES_USER`, default `postgres`), used only at initialisation and by backup tooling. Not a Kiban role. | `POSTGRES_USER` | |
| Owner role | The non-superuser Postgres role `kiban` that owns the application database; migrations and bootstrap connect as it. | `KIBAN_DB_PASSWORD` | |

## Authorization

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Tuple | One `object # relation @ subject` row. | `authz.tuple` | |
| Grant | The act, and the API, of writing tuples. | `POST /api/auth/grants`, `store.Grant` | |
| Default grant | The once-only seeding of the company-module admin relation for a new company. | `authz.default_grant` | |
| Check | The raw engine relation test. Not a synonym for a decision. | `engine.Check` | |
| Decision | The ordered, fail-closed evaluation of a `can` question. | `decision.Evaluate` | |
| Effective-access API | The HTTP surface for decisions: `can`, batch decisions, summary. Say "batch decision" in prose. | `/api/auth/effective-access/*` | batchCan |
| Scope | `global` or `company`: the reach of a decision or a module. List filters use `view`, never `scope`. | `decision.Request.Scope`, manifest `scopeType` | |
| Base model | The relation graph embedded in the engine: system, company, company module, member, position, group. | `internal/authz/engine/model.json` | reference model |
| Member relation | `company#member` and `company_module#member`: a company's active, linked members, administrators included. Written by org on member create and deactivate. | relation `company#member` | |
| Anchor | The `company_module` tuple every module object carries, written by the module at creation; binds the object to one company for every decision. | relation `<type>#company_module` | |
| Authorization fragment | A module's own object types, relations and feature keys, layered on the base model. | `authz.fragment.json` | |
| Effective model | The base model merged with every enabled module's fragment. | `fragment.Load` | |
| Feature key | `module.scope.action`, declared in a fragment. | | |
| Capability | A module's installed and enabled state, and the three capability errors the gateway can answer with. | | |
| Entitlement | Licensing state; dormant in 0.1. | | |
| Policy | Always qualified by its subject: MFA policy, password policy, webhook target rules. Field and row policy are not built. | | |

## Organization

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Tenant | One deployment. | | |
| Company | The org-unit type that anchors membership and authorization. A company is always a root org unit and a root org unit is always a company. | `org_unit_type.is_company`, `org.checkCompanyIsRoot` | root |
| Org unit | A node of the typed tree. | `org.org_unit` | |
| Position | A slot on an org unit. | `org.position` | |
| Assignment | Who holds a position and for which dates, as a half-open interval. | `org.position_assignment` | |
| Holder | The member currently assigned to a position. | relation `position#holder` | |
| Group | A company-scoped set of members. | `org.group` | team |

## Audit and events

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Audit Event | An immutable record that an actor performed an action on a subject at a time. Append-only. | `audit.<service>__events`, `audit.Event` | |
| Module Custom Event | A module-originated payload posted to the notification module that fans out into messages; its shape is the module's own. | `POST /internal/notification/v1/companies/{companyId}/events` | notification event |
| Notification Message | One delivered item in a subscriber's inbox. | `notification.message` | |

## Modules and runtime

| Term | Meaning | Code anchor | Instead of |
|---|---|---|---|
| Module | A contract-conforming package: manifest, authorization fragment, module OpenAPI, migrations, optional routes. | `modules/<key>/` | |
| Foundation service | Registry, identity, org, authz, gateway. Not modules. | `cmd/*` | |
| modulekit | The Apache-2.0 Go package a module service is built on: token verifier, HTTP helpers, authorization, org and notification clients. | `modulekit/` | |
| Manifest | A module's declaration of key, version, scope, service and schema. | `module.manifest.json` | |
| Catalog | The registry's table of known modules. | `platform.module_catalog` | |
| Module OpenAPI | A module's HTTP API description. | `openapi.yaml` | API fragment |
| Installed, enabled, mandatory | Registry lifecycle states. "Active" is reserved for `is_active` rows: say "enabled module", "active member", "active company". | `platform.module_installation` | |
| DocShare | The document-sharing sample module; its records are files. The module key stays `docs`. | `modules/docs` | |

## Process

| Term | Meaning |
|---|---|
| Gate | `make check` and `make test`; also a decision step ("the membership gate"). |
| Guard | Code that refuses: `RequireSuperadmin`, the live-stack guard. |
| Proof script | The `curl-proof.sh` and `e2e-*.sh` scripts that exercise a live stack. |
| Browser end-to-end test | Playwright suites under `web/*/e2e`. |
| Differential harness | The `make test` step that compares the authorization engine against OpenFGA (65 vectors, mutation and cycle proofs, 5000 generated checks). |
| Live test | Go tests behind the `live` build tag. |
| Known limitation | A release-facing statement of what does not work yet. |
| Compose project | `kiban` (development or public) or `kiban-test` (isolated tests). |
