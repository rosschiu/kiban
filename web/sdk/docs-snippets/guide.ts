// SPDX-License-Identifier: Apache-2.0

// The code samples of the public SDK guide (the site's sdk-guide.md page) and of the
// "Integrate your app" page's frontend track, kept as compilable functions so the pages cannot
// drift from the package: `npm run -w sdk typecheck` compiles this file, and test/guide.test.ts
// runs it against a mocked fetch. Edit the pages and this file together.
import {
  ApiErrorCode,
  KibanApiError,
  createApiClient,
  createCanI,
  createEffectiveAccessClient,
  createGrantObjectAccess,
  createMemoryStorage,
  createOrgClient,
  createSession,
  type ApiClient,
  type Page,
  type Session
} from "../src/index.js";

const gatewayOrigin = "https://127.0.0.1:8443";

// "Create a session"
export function persistedSession(fetchFn?: typeof fetch): Session {
  return createSession({
    authOrigin: gatewayOrigin,
    realm: "kiban",
    clientId: "kiban-frontend",
    redirectUri: "http://localhost:5173/callback.html",
    persistTokens: true,
    fetchFn
  });
}

// "Where tokens live": memory-only alternative
export function memoryOnlySession(fetchFn?: typeof fetch, navigate?: (url: string) => void): Session {
  return createSession({
    authOrigin: gatewayOrigin,
    realm: "kiban",
    clientId: "kiban-frontend",
    redirectUri: "http://localhost:5173/callback.html",
    storage: createMemoryStorage(),
    fetchFn,
    navigate
  });
}

// "The API client"
export function apiClient(session: Session, fetchFn?: typeof fetch): ApiClient {
  return createApiClient({
    baseUrl: gatewayOrigin,
    getAccessToken: () => session.getAccessToken(),
    getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
    refreshAccessToken: () => session.refresh(),
    fetchFn
  });
}

// "The clients": summary for the first company, then a batch object check
export async function visibleDocuments(api: ApiClient): Promise<string[]> {
  const effectiveAccess = createEffectiveAccessClient(api);
  const org = createOrgClient(api);

  const companies = await org.meCompanies();
  const summary = await effectiveAccess.summary(companies[0]?.id);

  const decisions = await effectiveAccess.batchCan({
    featureKey: "docs.create",
    moduleKey: "docs",
    scope: "company",
    companyId: summary.companyId,
    items: [
      { object: { type: "docs_document", id: "doc-1" }, relation: "viewer" },
      { object: { type: "docs_document", id: "doc-2" }, relation: "viewer" }
    ]
  });
  return decisions.filter((d) => d.decision.allowed).map((d) => d.object.id);
}

// "Recipes": canI
export async function canIChecks(api: ApiClient, companyId: string): Promise<{ admin: boolean; view: boolean; reason: string }> {
  const canI = createCanI(createEffectiveAccessClient(api));

  const admin = await canI({
    featureKey: "auth.platform_administration.access",
    requiredPlatformRole: "kiban-superadmin"
  });

  const view = await canI({ featureKey: "core.company.view", companyId });
  return { admin: admin.allowed, view: view.allowed, reason: view.reason };
}

// "Recipes": grantObjectAccess / revokeObjectAccess
export async function shareWithGroup(api: ApiClient, companyId: string): Promise<void> {
  const { grantObjectAccess, revokeObjectAccess } = createGrantObjectAccess(api);

  await grantObjectAccess({
    companyId,
    objectType: "docs_document",
    objectId: "doc-1",
    relation: "viewer",
    subjectType: "group",
    subjectId: "group-12",
    subjectRelation: "member"
  });

  await revokeObjectAccess({
    companyId,
    objectType: "docs_document",
    objectId: "doc-1",
    relation: "viewer",
    subjectType: "group",
    subjectId: "group-12",
    subjectRelation: "member"
  });
}

// "Error handling"
export async function createGroupOrExplain(api: ApiClient, session: Session, companyId: string): Promise<string> {
  const org = createOrgClient(api);
  try {
    await org.adminCreateGroup(companyId, { code: "sales", name: "Sales" });
    return "created";
  } catch (err) {
    if (!(err instanceof KibanApiError)) throw err;
    switch (err.code) {
      case ApiErrorCode.AuthTokenMissing:
      case ApiErrorCode.AuthTokenInvalid:
        void session.login();
        return "login";
      case ApiErrorCode.Forbidden:
      case ApiErrorCode.AuthorizationDenied:
        return "hide";
      case ApiErrorCode.ModuleDisabled:
      case ApiErrorCode.ModuleNotInstalled:
        return "module-off";
      case ApiErrorCode.ValidationFailed:
      case ApiErrorCode.Conflict:
        return `user: ${err.message}`;
      case ApiErrorCode.AuthorizationUnavailable:
        return "retry";
      default:
        throw err;
    }
  }
}

// Integrate your app, "Gate a route on login": a protected route calls this first. It returns
// false after starting the redirect to Keycloak, so the caller renders nothing.
export async function requireLogin(session: Session): Promise<boolean> {
  if (session.isAuthenticated()) return true;
  await session.login();
  return false;
}

// Integrate your app, "Finish the login": the callback route, once on load.
export async function finishLogin(session: Session, callbackUrl: string): Promise<void> {
  await session.handleCallback(callbackUrl);
}

// Integrate your app, "Ask before showing a feature": a module feature in one company.
export async function canSeeInbox(api: ApiClient, companyId: string): Promise<boolean> {
  const canI = createCanI(createEffectiveAccessClient(api));
  const inbox = await canI({ featureKey: "notification.inbox.view", moduleKey: "notification", companyId });
  return inbox.allowed;
}

// Integrate your app, "Call a module endpoint": the SDK has no client for a sample module, so
// `api.request` takes the path from the module's OpenAPI file and unwraps the envelope.
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

// Integrate your app, "Log out".
export function signOut(session: Session): void {
  session.logout();
}
