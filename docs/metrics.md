# Metrics

The platform has one scrape target: `GET /api/platform/metrics` on the gateway. It returns a
single Prometheus text exposition (`text/plain; version=0.0.4`) that merges the gateway's own
registry with the `/metrics` of registry, identity, org, authz and every installed and enabled
module, fetched concurrently on the internal network with a 2 s timeout per target. Every
service also keeps exposing `GET /metrics` on its own internal listener (the compose-internal
host:port its `/health` answers on, never published to the host and never routed through the
gateway's module proxy) for a Prometheus that lives inside the network.

## The aggregated exposition

- Every series carries a `service` label naming the service that emitted it (`gateway`,
  `registry`, `identity`, `org`, `authz`, or the module key). The label is set by the gateway
  when it merges the scrapes; a service's own `/metrics` carries the same label already.
- Metric families with the same name from several services (the standard set, for instance)
  are emitted once under one `# HELP`/`# TYPE` header with every service's samples beneath it.
- One extra gauge, `kiban_metrics_scrape_up{service}`, reports the scrape itself: `1` when that
  service's `/metrics` answered, `0` when it failed, timed out, or returned something that is
  not an exposition. A failed target contributes nothing else, and the response is still
  `200`: alert on `kiban_metrics_scrape_up == 0`, not on the scrape failing.
- The gateway scrapes a module only while its catalog entry is installed and enabled; a
  disabled module simply disappears from the exposition (no `kiban_metrics_scrape_up` series
  for it).
- The response body is capped at 8 MiB across all upstreams; a target whose body would exceed
  what is left of that budget is reported as `kiban_metrics_scrape_up 0`.

### Access

The route sits behind the same superadmin guard every `/api/platform/admin/*` mutation uses
(`internal/gateway.RequireSuperadmin`): the scraper needs a superadmin bearer. A scoped
read-only scrape credential is not offered today, so a Prometheus outside the network scrapes
with a superadmin's token (short-lived, obtained the way a login obtains one) or runs inside
the network against the per-service endpoints instead. The gateway itself has no bare
`/metrics`: its only listener is the edge (in public mode the shared Traefik forwards the whole
host to it), so an unauthenticated mount would be reachable from the internet
(`internal/gateway/metrics_public_exposure_test.go` pins this).

### Internal endpoints

| Service | Port | Metrics |
|---|---|---|
| gateway | 8443/8090 (edge) | no bare `/metrics`; the aggregated operator route only |
| registry | 8110 | standard + DB pool |
| identity | 8120 | standard + DB pool |
| org | 8130 | standard + DB pool |
| authz | 8140 | standard + DB pool + authz decisions |
| notification | 8150 | standard + DB pool + delivery jobs |
| timesheet | 8160 | standard + DB pool |
| docs | 8170 | standard + DB pool |
| helpdesk | 8180 | standard + DB pool |

A gateway-forwarded `/api/<module>/metrics` keeps its `/api/<module>` path prefix all the way to
the module's mux, which only registers routes under its base path or the bare `/metrics`, so the
two never collide (`internal/gateway/internal_exposure_test.go` and
`internal/gateway/metrics_exposure_test.go` prove this both ways).

## Metric table

Every metric carries a `service` label identifying which of the services above emitted it
(`kiban_build_info` additionally carries `version`/`commit`; the family-specific tables below
list only the labels beyond `service`).

### Standard set (every service)

| Name | Type | Labels (beyond `service`) | Meaning | Emitted by |
|---|---|---|---|---|
| `http_requests_total` | counter | `route`, `method`, `status` | Total HTTP requests handled, keyed by the mux route pattern, never the raw path (see the cardinality rule). | all 9 services |
| `http_request_duration_seconds` | histogram | `route`, `method`, `status` | Request handling latency. | all 9 services |
| `http_requests_in_flight` | gauge | (none) | Requests currently being handled. | all 9 services |
| `kiban_build_info` | gauge (always 1) | `version`, `commit` | Identifies the running build. `version` is the root `VERSION` file contents, baked in at `go build` time via `-ldflags`; `commit` is the short git SHA, or `"unknown"` when not supplied at build time; `make images` stamps the short git SHA. | all 9 services |
| `kiban_db_pool_acquired_conns` | gauge | (none) | Currently acquired connections in the service's `pgxpool.Pool`, read live from `pool.Stat()` at scrape time. | registry, identity, org, authz, notification, timesheet, docs, helpdesk (not gateway, which has no DB pool) |
| `kiban_db_pool_idle_conns` | gauge | (none) | Currently idle pool connections. | same 8 |
| `kiban_db_pool_max_conns` | gauge | (none) | Configured pool maximum. | same 8 |

### authz-only

| Name | Type | Labels (beyond `service`) | Meaning |
|---|---|---|---|
| `kiban_authz_decisions_total` | counter | `reason` | Effective-access decisions by outcome: one of the 13 frozen reason codes (`internal/authz/decision.Reason`, `ALLOWED` included). Recorded only for the two enforcement endpoints, `POST /internal/authz/effective-access/can` and `.../batch-can` (one increment per batch item). The `/effective-access/summary` endpoint's internal decisions are not recorded: they compose a display read across every feature and module rather than answer one enforcement question. |
| `kiban_authz_decision_duration_seconds` | histogram | (none) | Latency of one `decision.Decider.Evaluate` call (batch calls record the batch's total latency divided evenly across its items). |

### notification-only

| Name | Type | Labels (beyond `service`) | Meaning |
|---|---|---|---|
| `kiban_delivery_jobs` | gauge | `state` (`pending`\|`done`\|`dead`) | Count of `notification.delivery_job` rows in the worker's `claim_group`, per state. Re-counted periodically (`Store.CountJobsByState`, every 15 s by default) rather than updated on each transition, so the delivery hot path never waits on a metrics call. |
| `kiban_delivery_attempts_total` | counter | `kind` (`email`\|`webhook`), `outcome` (`success`\|`retry`\|`dead`) | One increment per delivery attempt, recorded inline when the attempt settles (`Worker.deliverLeased`/`failJob`). `dead` covers both the immediate dead-letter path for a non-retryable delivery and the retry ladder's max-attempts exhaustion. |

### gateway-only

| Name | Type | Labels (beyond `service`) | Meaning |
|---|---|---|---|
| `kiban_gateway_upstream_requests_total` | counter | `module`, `status` | One increment per module-proxy request the gateway forwarded. A request rejected before reaching the upstream (`MODULE_NOT_INSTALLED`, `MODULE_DISABLED`, `MODULE_DEPENDENCY_MISSING`) is not counted, since no upstream call was made. `status` is the HTTP status code the gateway wrote back, including 503 on an unreachable upstream. |
| `kiban_gateway_upstream_duration_seconds` | histogram | `module` | Latency of the proxied call itself (from immediately before the outbound request to the response being written), excluding catalog-lookup and capability-check time. |

## Route-label cardinality rule

`route` is always the Go 1.22+ mux pattern the request matched (`r.Pattern`, read after the
request has been routed; `internal/obs/metrics.Registry.Middleware`'s doc comment has the
mechanics), for example `GET /api/helpdesk/v1/companies/{companyId}/tickets`. It is never the
raw request path. A request that matches no registered pattern (a raw 404, or anything reaching
a handler outside `ServeMux` pattern dispatch) is labeled `"unmatched"`, not the path that
produced it, so an attacker-controlled 404 storm cannot create unbounded label cardinality.

## Prometheus scrape config

One target, the gateway's operator route, with a superadmin bearer:

```yaml
scrape_configs:
  - job_name: kiban
    scheme: https
    metrics_path: /api/platform/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/kiban-superadmin-token
    static_configs:
      - targets: ["gateway:8443"]
    scrape_interval: 15s
```

The bearer must be a valid superadmin access token; Prometheus re-reads `credentials_file` on
every scrape, so a sidecar that refreshes the token keeps the target authenticated. A
Prometheus instance deployed on the same compose network as the stack (`infra/compose.yaml`)
can instead scrape each service's internal `/metrics` directly (hostname is the compose service
name, ports as in the table above) and needs no credential for those; the gateway is still
only reachable through the operator route. Kiban does not ship a Prometheus instance; that is
the operator's deployment choice.

The gateway does not offer a per-module metrics proxy route (`/api/<module>/metrics`): fanning
every module's metrics out through per-module gateway routes would make the gateway's
route-label set a function of which modules happen to be installed (see the cardinality rule
above). The one aggregated route has a single, fixed route label.

## What to alert on first

- **Authz denial reasons spiking.** A sudden rise in
  `rate(kiban_authz_decisions_total{reason!="ALLOWED"}[5m])`, especially concentrated on one
  `reason`, is the highest-value signal this metric set carries. `DEPENDENCY_UNAVAILABLE` means
  one of authz's upstreams (identity, registry, org) is down; `COMPANY_ACCESS_BLOCKED` means a
  lockout affecting real users. Authz denials are invisible everywhere else: a 403 to the caller
  looks the same whether it is an expected permission boundary or a platform outage.
- **Delivery dead-letter growth.** `kiban_delivery_jobs{state="dead"}` trending up, or
  `rate(kiban_delivery_attempts_total{outcome="dead"}[15m]) > 0` sustained, means notification
  or webhook deliveries are being permanently dropped. Investigate the target (webhook endpoint
  down, SMTP misconfigured) before the backlog grows further.
- **5xx rate.** `rate(http_requests_total{status=~"5.."}[5m])` per service. A sustained non-zero
  rate on a foundation service (registry, identity, org, authz) is worse than the same rate on a
  module, since every module's request path depends on those services staying up.
- **DB pool saturation.** `kiban_db_pool_acquired_conns / kiban_db_pool_max_conns` approaching 1
  on any service is an early warning of request queuing and latency about to get much worse.
  Check this before `http_request_duration_seconds` p99 starts moving, not after.
- **Gateway upstream latency and errors.** `kiban_gateway_upstream_duration_seconds` p99 per
  `module`, and `rate(kiban_gateway_upstream_requests_total{status="503"}[5m])`. This is the
  gateway's view of whether a module is reachable and fast, independent of that module's
  self-reported `http_request_duration_seconds`. If the module reports fast handling but the
  gateway sees slow upstream calls, the gap is in the network or proxy layer.

## How this page is kept true

This page is the source of truth for the metric set. `internal/obs/metrics`'s unit test
(`metrics_test.go`) parses the tables above and fails if the package registers a metric the
tables do not list, or lists one the package cannot register. The same package's
`docs_metrics_live_test.go` (build-tagged `live`, kiban-test only) scrapes every running
service's `/metrics` and fails if any name above is never observed, and proves the aggregated
operator route carries every service's series with `kiban_metrics_scrape_up` at `1` for each.

## See also

- [Concepts](concepts.md): service topology (the gateway is the only edge)
- `internal/authz/decision`: the 13-reason enum `kiban_authz_decisions_total{reason}` reports
- [Building on Kiban](building.md): module ports and base paths
