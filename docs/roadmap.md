# Roadmap

Planned, in no particular order; nothing is promised for a date. Shipped items move to the [changelog](changelog.md).

- App and sample installation entirely through the API (register, enable, retire), no environment variables, the way an OpenFGA store and model are written
- Service clients created, rotated and revoked through the API, secret returned once, the way Keycloak registers a client
- Decisions resolved from the feature declaration: one string is one feature, the manifest is the only source of truth for what it checks
- Hosting Kiban under a path prefix such as `https://example.com/id`: today `KIBAN_DOMAIN` takes a host name only, the gateway owns `/auth`, `/realms`, `/resources`, `/api` and `/` at the root, and Keycloak's pages link to root paths
- Native (mobile) login guide and a refresh-token policy for mobile sessions
- List the objects a subject may reach through a relation (OpenFGA's ListObjects), for the app's own types: filtered by object type and company, sorted, cursor-paginated, so a large list never comes back whole; and checks about a third subject for an app
- Apps enabled per company, and self-service app registration for a company administrator
- Runtime dependency resolution between modules
- One error code across modules when a foundation service is unavailable
- Modulekit passes an upstream `401` through instead of answering `503`
- Audit trail API
- Kubernetes as a supported deployment path
- Passkey challenge at login when the policy requires one
- Field- and row-level policy on member data
- Writer for the `archived` user state
- Wider differential harness and the concurrent batch check on the request path
- Later: commercial module packaging, Entra ID and SCIM federation, all-in-one image, admin consoles
