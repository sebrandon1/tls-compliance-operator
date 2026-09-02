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

1. **Controller** watches Services, Ingresses, Routes, and Gateway API resources (HTTPRoute, TLSRoute, GRPCRoute, Gateway) for changes; periodically scans Pods and `TLSComplianceTarget` CRs. Headless services are resolved via the EndpointSlice API. NodePort services are probed on each node address; LoadBalancer services include ingress IP/hostname endpoints.
2. **Endpoint Resolver** extracts TLS endpoints (host:port) from each resource type. User-specified hosts (ExternalName services, Ingress TLS hosts, Route hosts, HTTPRoute/TLSRoute/GRPCRoute hostnames) are checked with `IsSafeHost()` so loopback, link-local/metadata, and RFC1918 addresses are not probed (SSRF). Cluster-internal addresses from Pods, NodePorts, ClusterIPs, and Gateway status are not filtered this way.
3. **TLS Checker** probes each endpoint with all TLS versions in parallel using Go's `crypto/tls`, then performs active ML-KEM probing for PQC readiness. After 3 consecutive Timeout or Unreachable failures, a circuit breaker skips that endpoint for 15 minutes.
4. **TLSComplianceReport** CR is created/updated with results
5. **Events and Metrics** are emitted for observability

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
| **Unreachable** | Could not connect to endpoint (unclassified network error) |
| **NoTLS** | Port is open but does not speak TLS |
| **PlaintextHTTP** | Port responds with HTTP and no TLS |
| **MutualTLSRequired** | Server requires a client certificate to complete handshake |
| **Pending** | Not yet checked |
| **Unknown** | Status could not be determined |

---

Next: [Viewing Reports](viewing-reports.md)
