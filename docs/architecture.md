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

1. **Controller** watches Services, Ingresses, Routes, and Gateway API resources (HTTPRoute, TLSRoute, Gateway) for changes; periodically scans all Pods. Headless services are resolved via the EndpointSlice API to discover individual pod endpoints.
2. **Endpoint Resolver** extracts TLS endpoints (host:port) from each resource type
3. **TLS Checker** probes each endpoint with all TLS versions in parallel using Go's `crypto/tls`, then performs active ML-KEM probing for PQC readiness
4. **TLSComplianceReport** CR is created/updated with results
5. **Events and Metrics** are emitted for observability

## Compliance Logic

| Status | Condition |
|--------|-----------|
| **Compliant** | Supports TLS 1.2 or 1.3 (supporting older versions alongside is fine) |
| **NonCompliant** | Only supports TLS 1.0/1.1 with no modern TLS |
| **Warning** | Partially compliant (reserved for future use) |
| **Timeout** | Connection timed out waiting for a response |
| **Closed** | Port is not listening (connection refused) |
| **Filtered** | No response and no explicit refusal (e.g. firewall drop) |
| **Unreachable** | Could not connect to endpoint (unclassified network error) |
| **NoTLS** | Port is open but does not speak TLS |
| **MutualTLSRequired** | Server requires a client certificate to complete handshake |
| **Pending** | Not yet checked |
| **Unknown** | Status could not be determined |

---

Next: [Viewing Reports](viewing-reports.md)
