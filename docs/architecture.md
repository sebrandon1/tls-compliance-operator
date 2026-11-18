# Architecture

## Component Diagram

```
+----------+  +-----------+  +--------+  +------+  +------------+  +-----------+
| Services |  | Ingresses |  | Routes |  | Pods |  | HTTPRoutes |  | TLSRoutes |
+----+-----+  +-----+-----+  +---+----+  +--+---+  | Gateways   |  +-----------+
     |              |             |          |       +-----+------+       |
     +---------+----+------+------+          |             |             |
               |           |         +-------v--------+   +------+------+
       +-------v-------+ +-v------+  | Periodic Pod   |          |
       | Endpoint      | | Route  |  | Scanner        |  +-------v--------+
       | Resolver      | | API    |  | (scan cycle)   |  | Gateway API    |
       | + EndpointSlice | Detect |  +-------+--------+  | Detection      |
       +-------+-------+ +---+---+          |            +-------+--------+
               |              |              |                    |
       +-------v--------------v--------------v--------------------v-------+
       |                       Endpoint Controller                        |
       |  - Creates TLSComplianceReport CRs                               |
       |  - Triggers async TLS checks (parallel version probing)           |
       |  - Active ML-KEM probing for PQC readiness                        |
       |  - Labels hostNetwork pod CRs                                     |
       |  - Emits Kubernetes events                                        |
       +-------+----------------------------------------------------------+
               |
       +-------v--------+     +-----------+
       | TLS Checker    |     | Webhook   |
       | (crypto/tls)   |     | Validator |
       | Rate Limited   |     | (Targets) |
       +-------+--------+     +-----------+
               |
       +-------v--------+
       | TLSCompliance  |
       | Report CR      |
       +----------------+
```

## Flow

1. **Controller** watches Services, Ingresses, Routes, and Gateway API resources (HTTPRoute, TLSRoute, GRPCRoute, Gateway) for changes; periodically scans Pods and `TLSComplianceTarget` CRs. Each kind is reconciled by its own controller and work queue (`endpoint-service`, `endpoint-ingress`, and so on), so a Service and an Ingress or Route with the same name are both discovered. Headless services are resolved via the EndpointSlice API. NodePort services are probed on each node address; LoadBalancer services include ingress IP/hostname endpoints. The `--include-namespaces` / `--exclude-namespaces` filter applies to the namespace of the source object. It is checked on reconcile, in the periodic scan, in cleanup (which deletes reports outside the filter), in run-once output and in the `endpoints_total` gauge. Cluster-scoped `TLSComplianceTarget`s are exempt.
2. **Endpoint Resolver** extracts TLS endpoints (host:port) from each resource type. User-specified hosts (ExternalName services, Ingress TLS hosts, Route hosts, HTTPRoute/TLSRoute/GRPCRoute hostnames) are checked with `IsSafeHost()` so loopback, link-local/metadata, and RFC1918 addresses are not probed (SSRF). Cluster-internal addresses from Pods, NodePorts, ClusterIPs, and Gateway status are not filtered this way. `TLSComplianceTarget` hosts get the same check in the controller, so the protection does not depend on the optional admission webhook.
3. **TLS Checker** probes each endpoint with all TLS versions in parallel using Go's `crypto/tls`, then performs active ML-KEM probing for PQC readiness. For `TLSComplianceTarget` and ExternalName endpoints, every dial runs through `hostvalidation.DialControl`, which rejects the resolved IP if it is reserved. This covers hostnames that resolve or rebind to loopback, metadata, or private addresses. Such reports end as `Unreachable` with a `LastError` that names the blocked address, and they are not retried. After 3 consecutive Timeout or Unreachable failures, a circuit breaker skips that endpoint for 15 minutes.
4. **TLSComplianceReport** CR is created/updated with results
5. **Events and Metrics** are emitted for observability

## Scheduling

The periodic scan is driven by `--scan-interval` (default `1h`).

- The first scan runs at startup, as soon as the informer caches are synced, and is
  **not** gated by the scan window.
- `--scan-window-start` / `--scan-window-end` (`HH:MM`) together with
  `--scan-window-timezone` confine scans to a daily window. Both bounds must be set
  and must differ; the operator exits at startup otherwise.
- When a tick fires outside the window, the cycle is skipped and a catch-up timer is
  armed for the next window open. When that timer fires, the scan runs and the ticker
  is reset, so the next scan is a full interval after the catch-up rather than
  immediately after the tick that was skipped.
- `--run-once` runs a single scan, reports the result, and returns without ever
  starting the loop.
- `--scan-interval` and the window flags are separate: a `1h` interval inside a
  `22:00–02:00` window yields at most four scans per night.

Two metrics expose this state: `tls_compliance_scan_cycle_next_scheduled_timestamp_seconds`
is the next expected cycle and is cleared to `0` when the operator shuts down, and
`tls_compliance_scan_cycle_skipped_total{reason}` counts cycles that did not run,
labelled `outside_window` or `invalid_window`. See [Metrics](metrics.md) for the
PromQL that distinguishes a closed window from a stalled loop.

## Compliance History

Each `TLSComplianceReport` keeps a bounded `status.history` audit trail of prior scan
results (default: 10 entries, configurable via `--max-history-entries`). Each history
entry records the scan timestamp, compliance status, cipher grade, supported TLS
versions, and certificate fingerprint.

History is appended only when compliance status, cipher grade, certificate
fingerprint, or TLS version support changes from the previous recorded entry.
Entries are stored newest-first; when the limit is exceeded, the oldest entries
are pruned. View the trail with `kubectl tlsreport describe <name>`.

## Compliance Logic

| Status | Condition |
|--------|-----------|
| **Compliant** | Supports TLS 1.2 or 1.3 (supporting older versions alongside is fine) |
| **NonCompliant** | Only supports TLS 1.0/1.1 with no modern TLS |
| **Warning** | Supports modern TLS (1.2/1.3) but also allows legacy versions (SSL 3.0/TLS 1.0/1.1) |
| **Timeout** | Connection timed out waiting for a response |
| **Closed** | Port is not listening (connection refused) |
| **Filtered** | Reserved for firewall-drop cases; the checker does not currently emit this status |
| **LocalhostOnly** | Every discovered bind address for the port is loopback, so the pod IP cannot reach it. Only produced with `--discover-listening-ports`; not a compliance failure |
| **Unreachable** | Could not connect to endpoint (unclassified network error) |
| **NoTLS** | Port is open but does not speak TLS |
| **PlaintextHTTP** | Port responds with HTTP and no TLS |
| **MutualTLSRequired** | Server requires a client certificate to complete handshake |
| **Pending** | Not yet checked |
| **Unknown** | Status could not be determined |

---

Next: [Viewing Reports](viewing-reports.md)
