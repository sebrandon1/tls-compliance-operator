# Architecture

## Component Diagram

```
+----------+     +-----------+     +--------+     +------+
| Services |     | Ingresses |     | Routes |     | Pods |
+----+-----+     +-----+-----+     +---+----+     +--+---+
     |                 |               |              |
     +--------+--------+-------+-------+              |
              |                |              +-------v--------+
      +-------v--------+  +---v-----------+  | Periodic Pod   |
      | Endpoint       |  | Route API     |  | Scanner        |
      | Resolver       |  | Detection     |  | (scan cycle)   |
      +-------+--------+  +-------+-------+  +-------+--------+
              |                    |                  |
      +-------v--------------------v------------------v-------+
      |                  Endpoint Controller                  |
      |  - Creates TLSComplianceReport CRs                    |
      |  - Triggers async TLS checks                          |
      |  - Labels hostNetwork pod CRs                         |
      |  - Emits Kubernetes events                            |
      +-------+-----------------------------------------------+
              |
      +-------v--------+
      | TLS Checker    |
      | (crypto/tls)   |
      | Rate Limited   |
      +-------+--------+
              |
      +-------v--------+
      | TLSCompliance  |
      | Report CR      |
      +----------------+
```

## Flow

1. **Controller** watches Services, Ingresses, and Routes for changes; periodically scans all Pods
2. **Endpoint Resolver** extracts TLS endpoints (host:port) from each resource type
3. **TLS Checker** probes each endpoint with all TLS versions using Go's `crypto/tls`
4. **TLSComplianceReport** CR is created/updated with results
5. **Events and Metrics** are emitted for observability

## Compliance Logic

| Status | Condition |
|--------|-----------|
| **Compliant** | Supports TLS 1.2 or 1.3 (supporting older versions alongside is fine) |
| **NonCompliant** | Only supports TLS 1.0/1.1 with no modern TLS |
| **Timeout** | Connection timed out waiting for a response |
| **Closed** | Port is not listening (connection refused) |
| **Filtered** | No response and no explicit refusal (e.g. firewall drop) |
| **Unreachable** | Could not connect to endpoint (unclassified network error) |
| **NoTLS** | Port is open but does not speak TLS |
| **MutualTLSRequired** | Server requires a client certificate to complete handshake |
| **Pending** | Not yet checked |

---

Next: [Viewing Reports](viewing-reports.md)
