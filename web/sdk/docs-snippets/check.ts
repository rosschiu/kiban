// SPDX-License-Identifier: Apache-2.0

// Compiles the exact snippets in web/sdk's recipe pages (recipes/*.md) via
// `npm run -w sdk typecheck`, which this file's tsconfig.json `include` entry pulls in. Never
// run — type-checked only. Kept out of src/ so tsup's build (entry: src/index.ts) never bundles
// it.
import {
  createApiClient,
  createCanI,
  createEffectiveAccessClient,
  createGrantObjectAccess,
  type ApiClient
} from "../src/index.js";

declare const session: {
  getAccessToken(): string | null;
  refresh(): Promise<string | null>;
};

function buildApiClient(): ApiClient {
  return createApiClient({
    baseUrl: "https://127.0.0.1:8443",
    getAccessToken: () => session.getAccessToken(),
    refreshAccessToken: () => session.refresh()
  });
}

// docs/recipes/canI.md
export async function canISnippet(): Promise<void> {
  const apiClient = buildApiClient();
  const effectiveAccess = createEffectiveAccessClient(apiClient);
  const canI = createCanI(effectiveAccess);

  const superadmin = await canI({
    featureKey: "auth.platform_administration.access",
    requiredPlatformRole: "kiban-superadmin"
  });
  if (superadmin.allowed) {
    // show the superadmin nav entry
  }

  const canViewCompany = await canI({
    featureKey: "core.company.view",
    companyId: "11111111-1111-1111-1111-111111111111"
  });
  if (!canViewCompany.allowed) {
    const reason: string = canViewCompany.reason;
    void reason;
  }
}

// docs/recipes/grantObjectAccess.md
export async function grantObjectAccessSnippet(): Promise<void> {
  const apiClient = buildApiClient();
  const { grantObjectAccess, revokeObjectAccess } = createGrantObjectAccess(apiClient);

  await grantObjectAccess({
    companyId: "1d2a6a4e-6f6f-4b9e-9c1e-1f2b3c4d5e6f",
    objectType: "docs_document",
    objectId: "doc-1",
    relation: "viewer",
    subjectType: "user",
    subjectId: "kc-sub-of-the-target-user",
    correlationId: crypto.randomUUID()
  });

  await revokeObjectAccess({
    companyId: "1d2a6a4e-6f6f-4b9e-9c1e-1f2b3c4d5e6f",
    objectType: "docs_document",
    objectId: "doc-1",
    relation: "viewer",
    subjectType: "user",
    subjectId: "kc-sub-of-the-target-user"
  });
}
