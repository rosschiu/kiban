# Roadmap

Planned, in no particular order; nothing is promised for a date. Shipped items move to the [changelog](changelog.md).

- Service-to-service credential (confidential client with the `kiban-api` audience) for Node.js, Python and Go backends
- Company, org unit and member creation through the gateway, plus an invite flow
- Configurable extra origins and redirect URIs, including custom schemes for Flutter and other native apps
- Native (mobile) login guide and a refresh-token policy for mobile sessions
- Published OpenAPI files with security schemes for client generation in any language
- REST-only integration guide for backends without an SDK
- Runtime module install from a manifest, without editing Go
- Runtime dependency resolution between modules
- One error code across modules when a foundation service is unavailable
- Modulekit passes an upstream `401` through instead of answering `503`
- Audit trail API
- `KIBAN_DOMAIN` passed to the gateway in the public Compose file (CORS)
- Kubernetes as a supported deployment path
- Passkey challenge at login when the policy requires one
- Field- and row-level policy on member data
- Writer for the `archived` user state
- Wider differential harness and the concurrent batch check on the request path
- Later: commercial module packaging, Entra ID and SCIM federation, all-in-one image, admin consoles
