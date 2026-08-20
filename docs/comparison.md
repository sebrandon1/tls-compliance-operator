# Feature Comparison: tls-compliance-operator vs openshift/tls-scanner

The [openshift/tls-scanner](https://github.com/openshift/tls-scanner) is a batch Job-based TLS auditing tool for OpenShift/Kubernetes. This operator is independently developed but inspired by the scanner's categorization model. The tables below summarize shared features, unique capabilities, and architectural differences.

## Shared Capabilities

| Feature | tls-compliance-operator | openshift/tls-scanner |
|---------|------------------------|-----------------------|
| TLS version detection (1.0-1.3) | Yes | Yes |
| Cipher suite reporting | Yes | Yes |
| Certificate details | Yes | Yes |
| Non-compliant endpoint flagging | Yes | Yes |
| Namespace filtering (exclude) | Yes | Yes |

## Operator-Only Features

| Feature | Description |
|---------|-------------|
| Continuous monitoring | Watches for resource changes in real time via controller |
| Prometheus metrics | `tls_compliance_*` gauge/counter/histogram metrics |
| Kubernetes events | Emits Warning/Normal events for compliance changes |
| CRD-based reporting | Results stored as `TLSComplianceReport` custom resources |
| OpenShift Route support | Detects and monitors Routes with TLS termination |
| Certificate expiry tracking | Reports days until expiry with configurable warning threshold |
| Rate limiting | Configurable rate limiter for TLS checks |
| Mutual TLS detection | Detects when server requires client certificate |
| Multi-arch support | Builds for amd64, arm64, s390x, ppc64le |
| Finer-grained failure statuses | Timeout, Closed, and Unreachable (Filtered is reserved in the API) |
| Include-mode namespace filtering | `--include-namespaces` for allow-list namespace monitoring |
| IANA/OpenSSL cipher name mapping | Bidirectional cipher suite name translation |
| Cipher strength grading (A-F) | Per-cipher and overall strength grades |
| OpenShift TLSSecurityProfile compliance | Checks against APIServer, IngressController, and KubeletConfig profiles |
| Arbitrary target scanning | `TLSComplianceTarget` CRD for scanning any host:port |
| Configurable worker pool | `--workers` flag for concurrent periodic scan throughput |
| CSV, JSON, YAML, JUnit, Markdown, HTML export | `kubectl-tlsreport` plugin for CI/CD integration, including snapshot diff |
| Post-quantum readiness detection | Reports negotiated key exchange curves and PQC status |
| Active ML-KEM probing | Dedicated TLS 1.3 handshake to confirm post-quantum key exchange support |
| Gateway API support | Auto-detects and monitors HTTPRoute, TLSRoute, and Gateway resources |
| Headless service scanning | Discovers endpoints via EndpointSlice API for StatefulSet pods |
| ALPN protocol detection | Reports negotiated ALPN (h2, http/1.1) per TLS version |
| Forward secrecy detection | Identifies ephemeral key exchange (ECDHE/DHE) across all cipher suites |
| SSL 3.0 detection | Probes for deprecated SSLv3 support |
| Webhook validation | Admission webhook validates TLSComplianceTarget resources |
| mTLS client certificates | Client cert support for probing mTLS-protected endpoints |
| Per-namespace rate limiting | Fine-grained TLS check rate control per namespace |
| Pod IP and hostNetwork scanning | Discovers TLS servers on pod IPs even without a Service/Ingress/Route |
| NodePort and LoadBalancer endpoints | Probes node addresses and load-balancer ingress in addition to ClusterIP |
| Run-once CI mode | `--run-once` scan with pass/fail exit codes |

## Architectural Differences

| Aspect | tls-compliance-operator | openshift/tls-scanner |
|--------|------------------------|-----------------------|
| Execution model | Long-running controller with periodic rescans | Batch Job (run once, collect results) |
| TLS probing | Go `crypto/tls` | nmap with TLS scripts |
| Output format | Kubernetes CRDs + events + Prometheus | Raw scan results / reports |
| Discovery | Service, Ingress, Route, Gateway API, Pod, NodePort/LoadBalancer | Pod-level endpoint scanning via lsof |
| Deployment | Operator (Deployment + CRDs) | Job or CronJob |
