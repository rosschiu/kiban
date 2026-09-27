# Integrate your app

Your application runs beside Kiban and keeps its own code, database and deployment. This page
connects it: the backend registers the app and talks to Kiban through an SDK, the frontend logs
users in through Kiban. It is written as numbered steps; each step says what to run and what you
should see.

## Which track

- **Backend track**: a Node, Python or Go backend (or any language with the REST API) that needs
  to know who the user is, ask "may they do this here?", and record who may see what.
- **Frontend track**: a browser application that needs login and the same question for its UI.
- **Administration**: creating the first company and its members, as a superadmin.
- **REST-only**: the routes behind the SDKs, for any language.

## Read this before you start

Three things 0.1 does not do. They shape the steps below.

1. **Registering an app, enabling it, and creating companies and members are superadmin
   work.** There is no self-service registration and no company-administrator delegation yet.
2. **Checks answer for the bearer only.** Your backend asks with the user's own token ("may
   this user") or its service token ("may I"). There is no "list every object this user may
   see" API yet.
3. **An app is enabled for the whole deployment**, not per company.

Every track assumes a running Kiban. `make dev` from a checkout gives you a gateway at
`https://127.0.0.1:8443`; the image quickstart gives you `http://localhost:3000`. See the
[Quickstart](quickstart.md). The samples use `tokidesk` as the app key; use your own.

## Backend track

The Node samples on this page are compiled and run against the SDK by its test suite; the Go
samples compile with the Go SDK; the same calls run end to end against a real stack in the
repository's live tests.

### 1. Give your backend a service client

Add a client id to `KIBAN_SERVICE_CLIENTS` in `.env` (comma-separated) and start the stack;
bootstrap creates a confidential Keycloak client with a service account and the `kiban-api`
audience. Read its secret in the Keycloak admin console: realm `kiban`, Clients,
`tokidesk-backend`, Credentials.

```
KIBAN_SERVICE_CLIENTS=tokidesk-backend
```

You should see `service client tokidesk-backend: applied` in bootstrap's log on the first run and
`converged` afterwards.

### 2. Write the manifest

One JSON document: the app key, the service client, the feature keys your code will ask about,
and the object types and relations your app owns. Every object type declares `company_module`
(the anchor that binds an object to a company) plus its own relations.

```json
{
  "key": "tokidesk",
  "displayName": "TokiDesk",
  "version": "1.0.0",
  "serviceClientId": "tokidesk-backend",
  "features": ["tokidesk.ticket.view", "tokidesk.ticket.edit", "tokidesk.reminders.run"],
  "authzFragment": {
    "ticket": {
      "company_module": { "this": true },
      "viewer": { "this": true },
      "editor": { "this": true }
    }
  }
}
```

Relations follow the base model's grammar (`this`, `computedUserset`, `tupleToUserset`); the
[Building](building.md#authorization-fragment-authzfragmentjson) page documents it. A type the
base model or another app already declares is refused.

### 3. Register and enable the app

As a superadmin (the token from
[Getting a token for the shell](#getting-a-token-for-the-shell)), once:

```
curl -sk https://127.0.0.1:8443/api/platform/admin/apps \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" -d @manifest.json
curl -sk -X POST https://127.0.0.1:8443/api/platform/admin/modules/tokidesk/enable \
  -H "Authorization: Bearer $TOKEN"
```

You should see `{"data":{"module":"tokidesk","installed":true,"enabled":false,...}}` from the
first call and `"enabled":true` from the second. Registering again with a higher `version`
updates the app in place; a bad manifest is a `422` naming the field. No restart happens.

### 4. Install the SDK

=== "Node"

    ```
    npm i @rosschiu/kiban-sdk
    ```

    The backend entry is `@rosschiu/kiban-sdk/server` (ESM, Node 20 or later, no runtime
    dependencies). GitHub Packages needs an authenticated read; see the
    [SDK guide](sdk-guide.md#install).

=== "Python"

    ```
    pip install ./sdk/python        # from a checkout; kiban-sdk on an index when published
    ```

    Python 3.10 or later; depends on PyJWT with its cryptography extra.

=== "Go"

    ```
    go get github.com/rosschiu/kiban/sdk
    ```

### 5. Create the client once at startup

=== "Node"

    ```ts
    import { createAppClient, createServiceCredentials, createTokenVerifier } from "@rosschiu/kiban-sdk/server";

    const gatewayOrigin = "https://127.0.0.1:8443";
    const credentials = createServiceCredentials({ gatewayOrigin, clientId: "tokidesk-backend", clientSecret });
    const kiban = createAppClient({ gatewayOrigin, appKey: "tokidesk", credentials });
    const verifier = createTokenVerifier({ gatewayOrigin });
    ```

=== "Python"

    ```python
    from kiban import KibanClient

    kiban = KibanClient(gateway_url="https://127.0.0.1:8443", client_id="tokidesk-backend", client_secret=SECRET)
    ```

=== "Go"

    ```go
    kiban, err := sdk.New(ctx, sdk.Config{GatewayURL: "https://127.0.0.1:8443", ClientID: "tokidesk-backend", ClientSecret: secret})
    ```

You should see no network call yet in Node and Python; the Go client fetches the realm's
signing keys at construction and fails loudly if the gateway is unreachable.

### 6. Verify the user's token on every request

Your frontend sends the user's Kiban access token as `Authorization: Bearer`. Verify it before
anything else: signature against the realm's keys, issuer, audience, expiry. The subject you get
back is who the user is and nothing more; never read a role from the token.

=== "Node"

    ```ts
    export async function requireUser(authorization: string | undefined): Promise<string> {
      const bearer = authorization?.replace(/^Bearer /, "");
      if (!bearer) throw new Error("login required");
      const user = await verifier.verify(bearer);
      return user.subject;
    }
    ```

=== "Python"

    ```python
    def require_user(authorization: str | None) -> str:
        bearer = (authorization or "").removeprefix("Bearer ")
        if not bearer:
            raise PermissionError("login required")
        return kiban.verify_user_token(bearer).subject   # raises jwt.InvalidTokenError otherwise
    ```

=== "Go"

    ```go
    func requireUser(ctx context.Context, kiban *sdk.Client, r *http.Request) (string, error) {
        bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        if bearer == "" {
            return "", errors.New("login required")
        }
        return kiban.VerifyUserToken(ctx, bearer)
    }
    ```

You should see the user's `sub` (their Keycloak id) for a valid token and an error for an
expired one, one for another audience, or one Kiban did not sign.

### 7. Ask before every read and write

One call with the user's own bearer: the feature key, your app key, the company, and for an
object read or write, the object and the relation. A denial is a normal answer with a reason,
never an exception.

=== "Node"

    ```ts
    const decision = await kiban.can(bearer, {
      featureKey: "tokidesk.ticket.view", moduleKey: "tokidesk", scope: "company", companyId,
      object: { type: "ticket", id: ticketId }, relation: "viewer"
    });
    if (!decision.allowed) return res.status(403).end();
    ```

=== "Python"

    ```python
    decision = kiban.can(bearer, "tokidesk.ticket.view", module_key="tokidesk", company_id=company_id,
                         object={"type": "ticket", "id": ticket_id}, relation="viewer")
    if not decision.allowed:
        abort(403)
    ```

=== "Go"

    ```go
    d, err := kiban.Can(ctx, bearer, sdk.CanRequest{
        FeatureKey: "tokidesk.ticket.view", ModuleKey: "tokidesk", CompanyID: companyID,
        Object: &struct{ Type string `json:"type"`; ID string `json:"id"` }{"ticket", ticketID}, Relation: "viewer",
    })
    ```

You should see `allowed: true` for a member of the company who holds `viewer` on the ticket,
`COMPANY_MEMBERSHIP_REQUIRED` for anyone else, `MODULE_DISABLED` while the app is not enabled,
and a `422` for a feature key your manifest does not declare.

### 8. Write tuples when things happen

When your app creates an object, write its anchor and its first relation in one call, with the
app's service token (the SDK obtains and refreshes it). The anchor binds the object to the
company; without it every check on the object is denied.

=== "Node"

    ```ts
    await kiban.grant(companyId, [
      kiban.anchorTuple("ticket", ticketId, companyId),
      { objectType: "ticket", objectId: ticketId, relation: "viewer", subjectType: "user", subjectId: creatorSubject }
    ]);
    ```

=== "Python"

    ```python
    kiban.grant(company_id, [
        kiban.anchor_tuple("tokidesk", "ticket", ticket_id, company_id),
        {"objectType": "ticket", "objectId": ticket_id, "relation": "viewer", "subjectType": "user", "subjectId": creator},
    ])
    ```

=== "Go"

    ```go
    err := kiban.Grant(ctx, companyID,
        sdk.AnchorTuple("tokidesk", "ticket", ticketID, companyID),
        sdk.Tuple{ObjectType: "ticket", ObjectID: ticketID, Relation: "viewer", SubjectType: "user", SubjectID: creatorSubject},
    )
    ```

`revoke` removes what `grant` wrote. You should see `403 AUTHORIZATION_DENIED` if you name
another app's object type and `422 VALIDATION_FAILED` for a base type such as `company`: an app
owns its own types and nothing else. A subject can also be a position (`subjectType:
"position"`) or a group, so access follows the chair or the membership.

### 9. Look the member up

The subject is enough for tuples. When your app needs the member record (a display name, a
position), ask org whether the subject is an active member of the company.

=== "Node"

    ```ts
    const fact = await kiban.memberBySubject(companyId, subject);   // { isMember, isActive, memberId }
    ```

=== "Python"

    ```python
    fact = kiban.member_by_subject(company_id, subject)              # MemberFact(is_member, is_active, member_id)
    ```

=== "Go"

    ```go
    fact, err := kiban.MemberBySubject(ctx, companyID, subject)
    ```

### 10. Background jobs

A worker, a connector or a mailer has no user. It asks for itself, with the service token, and
is authorized by whatever an administrator granted the app's service account.

=== "Node"

    ```ts
    const decision = await kiban.canService({ featureKey: "tokidesk.reminders.run", moduleKey: "tokidesk", scope: "company", companyId });
    ```

=== "Python"

    ```python
    decision = kiban.can_service("tokidesk.reminders.run", module_key="tokidesk", company_id=company_id)
    ```

=== "Go"

    ```go
    d, err := kiban.CanService(ctx, sdk.CanRequest{FeatureKey: "tokidesk.reminders.run", ModuleKey: "tokidesk", CompanyID: companyID})
    ```

## Where the user's token lives

Two shapes work with Kiban as shipped; the choice is the app's, not a Kiban setting.

- **The browser holds the token.** The frontend track below: the browser SDK logs the user in,
  keeps the token in session storage, and the browser calls Kiban and your app with it. Simple,
  and it fits any static frontend. A script that manages to run in the page could read the
  token, so a strict content security policy matters.
- **Your backend holds the token.** The user logs in, your backend receives the token and keeps
  it server-side, and gives the browser its own httpOnly cookie for the session, the shape an app
  with an existing cookie session already has. The browser never sees a Kiban token; your backend
  calls Kiban with the SDK and the token it holds, and your existing CSRF protection stays as it
  is. Register your backend's callback URL as the login's redirect URI (`KIBAN_EXTRA_ORIGINS`) and
  exchange the code there.

## Frontend track

Every TypeScript snippet on this page is compiled and run against the SDK by its test suite, so
it works against the package as shipped.

### 1. Register your application's origin

Keycloak only completes a login whose `redirect_uri` is registered on the `kiban-frontend`
client. Bootstrap writes that list on every start of the stack:

- With `KIBAN_DOMAIN` unset (the default for `make dev` and the image quickstart), the list is
  fixed: `http://localhost:3000/*`, `http://localhost:5173/*`, `http://localhost/*`,
  `https://127.0.0.1:8443/*` and the test stack's `https://127.0.0.1:18543/*`. A development
  server on `http://localhost:5173` or `http://localhost:3000` works without any change.
- With `KIBAN_DOMAIN=app.example.com` (the `make public-up` path sets it from
  `KIBAN_PUBLIC_HOST`), the list becomes exactly `https://app.example.com/*` and nothing else.
  Your application must be served from that origin, or behind the same reverse proxy as the
  gateway.

For any other origin, add it to `KIBAN_EXTRA_ORIGINS` in `.env` (comma-separated) and restart
the stack: a web origin such as `https://app.example.com` is allowed to complete the login and
joins the gateway's CORS allow-list; a custom scheme such as `com.example.app:/callback` is a
native app's redirect URI. Bootstrap reconciles the client's lists to `KIBAN_DOMAIN` plus this
variable on every start, so an edit in the Keycloak admin console lasts only until the next
start; the variable is the place.

You should see: after the change, a login started from your origin lands back on your callback
route instead of Keycloak's "Invalid parameter: redirect_uri" page.

### 2. Install the SDK

The package is on GitHub Packages, which needs an authenticated read even for public packages:
a personal access token with the `read:packages` scope.

```
# .npmrc, next to your package.json
@rosschiu:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

```
npm i @rosschiu/kiban-sdk
```

You should see `@rosschiu/kiban-sdk` in `package.json`. The package is ESM only and has no
runtime dependencies; it needs `fetch` and `crypto.subtle`, which every current browser has.

### 3. Create the session

One session object per application, created once at startup. `authOrigin` is the gateway; the
SDK never talks to Keycloak directly.

```ts
import { createSession } from "@rosschiu/kiban-sdk";

const gatewayOrigin = "https://127.0.0.1:8443";

const session = createSession({
  authOrigin: gatewayOrigin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
  persistTokens: true
});
```

`persistTokens: true` writes the token set to `sessionStorage` under `kiban.oidc.tokens` so a
reload keeps the session; the entry goes away when the tab closes. Leave it off to keep tokens
in memory only.

You should see nothing yet: `session.isAuthenticated()` is `false` until step 4 completes.

### 4. Gate a route on login and finish the login

A protected route asks the session first. When the user is signed out the SDK records a PKCE
transaction and sends the browser to Keycloak; the function returns `false` so the route
renders nothing.

```ts
export async function requireLogin(session: Session): Promise<boolean> {
  if (session.isAuthenticated()) return true;
  await session.login();
  return false;
}
```

The callback route (`redirectUri` above) exchanges the code once on load. The call is
idempotent for the same code, so a React StrictMode double effect does not exchange it twice.

```ts
export async function finishLogin(session: Session, callbackUrl: string): Promise<void> {
  await session.handleCallback(callbackUrl);
}
```

Call it as `finishLogin(session, window.location.href)`, then navigate to your application's
home.

You should see: the browser goes to
`https://127.0.0.1:8443/auth/realms/kiban/protocol/openid-connect/auth?...code_challenge_method=S256`,
shows the Keycloak login page, and returns to your callback route with `code` and `state` in
the query. After `finishLogin`, `session.isAuthenticated()` is `true`. On a `make dev` stack the
first login as the superadmin also forces a password change.

### 5. Build the API client

Every request goes through one client that attaches the bearer and a correlation id, unwraps
the `{ data }` envelope and turns `{ error }` into a `KibanApiError`.

```ts
import { createApiClient } from "@rosschiu/kiban-sdk";

const api = createApiClient({
  baseUrl: gatewayOrigin,
  getAccessToken: () => session.getAccessToken(),
  getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
  refreshAccessToken: () => session.refresh()
});
```

You should see: `await createOrgClient(api).meCompanies()` returns the companies the user is an
active member of. For a freshly bootstrapped stack that is `[]` even for the superadmin: nobody
is a member of anything until a company and a member exist (see the REST-only track's escape
hatch, or the finding "Read this before you start", point 2).

### 6. Ask before showing a feature

`canI` answers "may this user use this feature, in this company?". A denial is a normal
`{ allowed: false, reason }`, never an exception. For a module feature, pass the module key; the
decision then also checks that the module is enabled for the company.

```ts
export async function canSeeInbox(api: ApiClient, companyId: string): Promise<boolean> {
  const canI = createCanI(createEffectiveAccessClient(api));
  const inbox = await canI({ featureKey: "notification.inbox.view", moduleKey: "notification", companyId });
  return inbox.allowed;
}
```

You should see `true` for an active member of `companyId` when the notification module is
enabled there, and `false` with a reason such as `COMPANY_MEMBERSHIP_REQUIRED` otherwise. The
request on the wire is `POST /api/auth/effective-access/can` with
`{ "featureKey": "notification.inbox.view", "moduleKey": "notification", "scope": "company", "companyId": "..." }`.
The gateway answers for the bearer only; a body naming another subject is rejected.

### 7. Call a module endpoint

The SDK has no typed client for the sample modules. `api.request` takes the path from the
module's OpenAPI file, and the gateway forwards it to the module unchanged. Paths follow
`/api/<module>/v1/...`.

```ts
export interface NotificationChannel {
  id: string;
  companyId: string;
  key: string;
  label: string;
  kind: "in_app" | "email" | "webhook";
  target: string | null;
  createdAt: string;
}

export async function listChannels(api: ApiClient, companyId: string): Promise<NotificationChannel[]> {
  const page = await api.request<Page<NotificationChannel>>(`/api/notification/v1/companies/${companyId}/channels`, {
    query: { page: 1, pageSize: 50 }
  });
  return page.items;
}
```

You should see an array (empty on a new stack). A `403` with code `MODULE_DISABLED` or
`MODULE_NOT_INSTALLED` means the module is off for this deployment; `AUTHORIZATION_DENIED` means
the module's own check (`notification.inbox.view` here) refused the bearer. The types come from
the module's [API reference](api/notification.html).

### 8. Handle 401 and refresh

The API client already does the common case: on a `401` it calls `session.refresh()` once
(concurrent callers share one refresh) and retries the request once. A second `401` is thrown
as a `KibanApiError`, so a rejected endpoint never loops. What is left for you is the branch on
the error code:

```ts
try {
  await org.adminCreateGroup(summary.companyId, { code: "sales", name: "Sales" });
} catch (err) {
  if (!(err instanceof KibanApiError)) throw err;
  switch (err.code) {
    case ApiErrorCode.AuthTokenMissing:
    case ApiErrorCode.AuthTokenInvalid:
      session.login(); // refresh already failed; start over
      break;
    case ApiErrorCode.Forbidden:
    case ApiErrorCode.AuthorizationDenied:
      // the caller may not do this; hide the control
      break;
    case ApiErrorCode.ModuleDisabled:
    case ApiErrorCode.ModuleNotInstalled:
      // the module is off for this deployment
      break;
    case ApiErrorCode.ValidationFailed:
    case ApiErrorCode.Conflict:
      // show err.message and err.details to the user
      break;
    case ApiErrorCode.AuthorizationUnavailable:
      // authz could not answer (503); retry later, never fail open
      break;
    default:
      throw err;
  }
}
```

You should see: an access token lives 300 seconds and the refresh token 30 minutes idle (the
realm's defaults). Within those limits the user never sees a login page again; past them the
`AuthTokenInvalid` branch starts a new login.

### 9. Log out

```ts
export function signOut(session: Session): void {
  session.logout();
}
```

You should see: the tokens are cleared, the browser goes to Keycloak's logout endpoint with the
ID token as `id_token_hint`, and comes back to the origin root of `redirectUri`
(`http://localhost:5173/`), not to the callback route. Pass `postLogoutRedirectUri` to
`createSession` for a different landing page; it must be registered on the client too.

For the full API and the recipes, see the [SDK guide](sdk-guide.md).


## Administration

A superadmin creates companies, org units and members through the gateway, with the token from
[Getting a token for the shell](#getting-a-token-for-the-shell). The sample shell's
administration pages do the same for positions and groups.

Create the company. A company has no parent; `typeKey` is `company`:

```
curl -sk https://127.0.0.1:8443/api/org/admin/units \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"typeKey":"company","parentId":null,"code":"acme","name":"Acme Ltd"}'
```

```json
{ "data": { "id": "<companyId>", "typeKey": "company", "parentId": null, "code": "ACME", "name": "Acme Ltd", "isActive": true } }
```

Creating an active company also grants every enabled app's and module's administrator relation
for it in the same transaction, so the company is never without an accountable administrator. An
org unit below the company is the same call with `"typeKey": "business_unit"` or `"territory"`
(the shipped taxonomy) and `"parentId": "<companyId>"`. Codes are normalised to upper case.

Create a member and link it to a login. `kcSub` is the `sub` claim of the user's token; the
identity record exists as soon as that user has made one request through the gateway (a login
followed by any API call):

```
curl -sk https://127.0.0.1:8443/api/org/admin/members \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"companyId":"<companyId>","code":"ross","displayName":"Ross Chiu","email":"ross@example.com"}'

curl -sk https://127.0.0.1:8443/api/org/admin/members/<memberId>/link-user \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"kcSub":"<sub>"}'
```

You should see the member with `"userId"` set after the link, and `GET /api/org/me/companies`
as that user now lists the company. `GET /api/org/admin/members?companyId=` lists a company's
members; `PUT /api/org/admin/members/{id}` updates one; `DELETE .../link-user` unlinks.

## REST-only track

### What you can and cannot do

- Every call needs a bearer: a user's access token from a browser login, or a service client's
  token from the client-credentials grant (below). A backend acts either on behalf of the user
  whose token it holds or as itself.
- Every response is an envelope: `{ "data": ... }` on success, `{ "error": { "code",
  "message", "details"? } }` on failure. Send `x-correlation-id` if you want to find the request
  in the gateway's logs and the audit rows; the gateway generates one otherwise.

### Route families

All on the gateway origin. The full contract is the [Platform API](api/platform.html).

| Family | What it is | Who may call it |
|---|---|---|
| `POST /api/auth/effective-access/can`, `.../batch-can` | The access decision for the bearer, one or many objects | Any bearer, for itself only |
| `GET /api/auth/effective-access/summary?companyId=` | Feature keys, role bindings and object grants the bearer holds | Any bearer, for itself only |
| `POST /api/auth/grants` | Write or remove relation tuples, bound to one company and one app or module | A registered app's backend, on its own object types; or a superadmin |
| `GET /api/org/companies/{id}/members/by-subject/{sub}` | Is this subject an active member, and which member | A registered app's backend, or a superadmin |
| `GET /api/org/me/companies` | Companies the bearer is an active member of | Any bearer |
| `GET /api/org/companies/{id}/members?q=&page=&pageSize=` | Member directory of one company | Active members of that company, or a superadmin |
| `/api/org/admin/units`, `/api/org/admin/members` | Company, org-unit and member administration | Superadmin |
| `/api/org/admin/companies/{id}/positions`, `.../groups`, `/api/org/admin/positions/{id}/assignments`, `/api/org/admin/groups/{id}/members` | Position and group administration | Superadmin |
| `POST /api/platform/admin/apps` | Register an app from its manifest | Superadmin |
| `GET /api/platform/capabilities[/{module}]`, `GET /api/platform/catalog` | What is registered, installed and enabled | Any bearer |
| `POST /api/platform/admin/modules/{key}/enable`, `.../disable`; `/api/platform/admin/platform-roles` | App and module enablement, the superadmin role | Superadmin |
| `/api/<module>/v1/...` | A built-in module's own API, forwarded unchanged | Whatever the module decides |

A minimal call:

```
curl -sk https://127.0.0.1:8443/api/auth/effective-access/can \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"featureKey":"core.company.view","scope":"company","companyId":"'"$COMPANY"'"}'
```

You should see `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[...]}}` for a member and
`allowed: false` with `COMPANY_MEMBERSHIP_REQUIRED` for anyone else. The gateway ignores any
subject named in the body and answers for the bearer.

### Getting a token for the shell

Because there is no direct grant for users, take the token from a browser session. Log in to
the sample shell (`https://127.0.0.1:8443`), open the browser's developer tools and run:

```js
JSON.parse(sessionStorage.getItem("kiban.oidc.tokens")).accessToken
```

The shell persists its tokens under that key. Export the value as `TOKEN`. It is valid for 300
seconds; take a fresh one when you get `401 AUTH_TOKEN_INVALID`. Its `sub` is your subject.

### Getting a token for a service

```
curl -sk https://127.0.0.1:8443/realms/kiban/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=tokidesk-backend -d client_secret=$SECRET
```

You should see a JSON body with `access_token`, valid for 300 seconds. Its `sub` is the client's
service-account user and its `azp` is the client id, which is how the gateway and the
authorization service recognise the app's backend. The SDKs do this for you.

## Next

- [SDK guide](sdk-guide.md): every client, the browser SDK and the backend entry.
- [Known limitations](limitations.md): what 0.1 does not do.
- [Building on Kiban](building.md): the in-tree module contract the sample modules follow.
