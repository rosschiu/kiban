// SPDX-License-Identifier: Apache-2.0

// The public "Integrate your app" page's backend samples for Node, compiled by the SDK's type
// check and run by test/server-guide.test.ts against a mocked gateway, so the page's code both
// compiles and behaves as the page says.
import { createAppClient, createServiceCredentials, createTokenVerifier, type AppClient, type TokenVerifier } from "../src/server/index.js";

export interface Backend {
  kiban: AppClient;
  verifier: TokenVerifier;
}

// 5. Create the client once at startup.
export function createBackend(gatewayOrigin: string, clientSecret: string, fetchFn?: typeof fetch): Backend {
  const credentials = createServiceCredentials({ gatewayOrigin, clientId: "tokidesk-backend", clientSecret, fetchFn });
  const kiban = createAppClient({ gatewayOrigin, appKey: "tokidesk", credentials, fetchFn });
  const verifier = createTokenVerifier({ gatewayOrigin, fetchFn });
  return { kiban, verifier };
}

// 6. Verify the user's token on every request: the subject is who they are, nothing more.
export async function requireUser(backend: Backend, authorization: string | undefined): Promise<string> {
  const bearer = authorization?.replace(/^Bearer /, "");
  if (!bearer) throw new Error("login required");
  const user = await backend.verifier.verify(bearer);
  return user.subject;
}

// 7. Ask before every read and write, with the user's own bearer.
export async function canViewTicket(backend: Backend, bearer: string, companyId: string, ticketId: string): Promise<boolean> {
  const decision = await backend.kiban.can(bearer, {
    featureKey: "tokidesk.ticket.view",
    moduleKey: "tokidesk",
    scope: "company",
    companyId,
    object: { type: "ticket", id: ticketId },
    relation: "viewer"
  });
  return decision.allowed;
}

// 8. Write tuples when things happen: the anchor binds the object to the company, the viewer
// relation gives the creator access.
export async function onTicketCreated(backend: Backend, companyId: string, ticketId: string, creatorSubject: string): Promise<void> {
  await backend.kiban.grant(companyId, [
    backend.kiban.anchorTuple("ticket", ticketId, companyId),
    { objectType: "ticket", objectId: ticketId, relation: "viewer", subjectType: "user", subjectId: creatorSubject }
  ]);
}

// 9. Look the member up when the app needs the member record, not just the subject.
export async function memberIdOf(backend: Backend, companyId: string, subject: string): Promise<string | null> {
  const fact = await backend.kiban.memberBySubject(companyId, subject);
  return fact.isMember && fact.isActive ? fact.memberId : null;
}

// 10. A background job asks for itself.
export async function mayRunReminders(backend: Backend, companyId: string): Promise<boolean> {
  const decision = await backend.kiban.canService({ featureKey: "tokidesk.reminders.run", moduleKey: "tokidesk", scope: "company", companyId });
  return decision.allowed;
}
