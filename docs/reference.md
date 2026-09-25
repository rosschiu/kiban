# Reference

Generated from the OpenAPI files and the SDK's TypeScript doc comments at build time, so they
match the code at the same commit.

## HTTP APIs

- [Platform API](api/platform.html): capabilities, effective access, grants, organization,
  superadmin operations (module enable/disable, platform-role grant and revoke), metrics.
  Generated from `internal/gateway/platform-openapi.yaml`.
- [Notification](api/notification.html)
- [DocShare (`docs`)](api/docs.html)
- [Helpdesk](api/helpdesk.html)
- [Timesheet](api/timesheet.html)

Every response uses one envelope: `{ "data": … }` on success, `{ "error": { "code", "message",
"details"? } }` on failure. Error codes are stable strings (`AUTH_TOKEN_MISSING`, `FORBIDDEN`,
`MODULE_DISABLED`, `AUTHORIZATION_UNAVAILABLE`, …). The sample modules' OpenAPI files omit some
status codes their handlers emit (see limitations).

### What the gateway mounts

Every route family, in one place. Everything under `/api/` needs a bearer unless noted.

| Family | Routes | Who |
|---|---|---|
| `/api/platform/*` | `GET capabilities`, `GET capabilities/{module}`, `GET catalog`; `POST admin/modules/{key}/enable`, `.../disable`; `POST admin/platform-roles`, `DELETE admin/platform-roles/{role}/{subjectId}`; `GET metrics`; `GET demo-mode` (no bearer) | Any user for reads; superadmin for `admin/*` and `metrics` |
| `/api/auth/effective-access/*` | `POST can`, `POST batch-can`, `GET summary?companyId=` | Any user, for the bearer only |
| `/api/auth/grants` | `POST` (grant or revoke tuples) | Superadmin |
| `/api/org/me/companies` | `GET` | Any user |
| `/api/org/companies/{id}/members` | `GET ?q=&page=&pageSize=` | Active members of the company, or a superadmin |
| `/api/org/admin/*` | `GET`/`POST companies/{id}/positions`, `POST positions/{id}/assignments`, `POST assignments/{id}/end`; `GET`/`POST companies/{id}/groups`, `GET`/`POST groups/{id}/members`, `DELETE groups/{id}/members/{memberId}` | Superadmin |
| `/api/<module>/v1/*` | Forwarded to the module unchanged, once it is installed and enabled | The module decides |
| `/auth/*`, `/realms/*`, `/resources/*` | Keycloak, without a bearer; `/auth/admin*` and the master realm answer `404` | Browser login |
| `/` | The sample shell | |

Company, org-unit and member creation are not mounted; see
[Integrate your app](integrate.md#escape-hatch-create-a-company-and-its-first-member).

## SDK

- [SDK guide](sdk-guide.md): install, session, clients, recipes, errors
- [SDK API reference](sdk/index.html)
- [Recipes](https://github.com/rosschiu/kiban/blob/main/web/sdk/RECIPES.md): `canI`, `grantObjectAccess`, `revokeObjectAccess`

## Contributing

- [Contributing](contributing.md): setup, gates, conventions, licensing of contributions

## Metrics

See the [Metrics](metrics.md) page. Each service exposes Prometheus metrics; the gateway's `GET /api/platform/metrics` requires a
superadmin bearer. `kiban_build_info{version,commit}` identifies the build.
