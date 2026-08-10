# Configuration Reference

The tls-compliance-operator is configured via command-line flags. Every flag
can also be set via an environment variable, which is useful when deploying
with Helm or kustomize overlays where modifying container args is inconvenient.

**Precedence:** CLI flag > environment variable > default value.

If a flag is set on the command line, its environment variable is ignored.

## Scanning

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--scan-interval` | `TLS_COMPLIANCE_SCAN_INTERVAL` | duration | `1h` | How often the operator re-checks all known TLS endpoints. Each cycle scans every Service, Ingress, Route, and Pod endpoint. Shorter intervals give faster detection but increase API server and network load. |
| `--cleanup-interval` | `TLS_COMPLIANCE_CLEANUP_INTERVAL` | duration | `5m` | How often the operator removes TLSComplianceReport CRs whose source resource (Service, Ingress, Route) has been deleted. |
| `--tls-check-timeout` | `TLS_COMPLIANCE_CHECK_TIMEOUT` | duration | `5s` | Timeout for each individual TLS connection attempt. The operator probes all TLS versions (1.0, 1.1, 1.2, 1.3, SSLv3) in parallel, so worst-case time per endpoint is roughly 1x this value plus a small overhead for the ML-KEM active probe. Increase on high-latency networks. |
| `--workers` | `TLS_COMPLIANCE_WORKERS` | int | `5` | Number of concurrent goroutines used during periodic scans. Range: 1-50. Higher values scan faster but use more CPU and network. This also controls `MaxConcurrentReconciles` for the controller work queue. |
| `--extra-tls-ports` | `TLS_COMPLIANCE_EXTRA_TLS_PORTS` | string | `""` | Comma-separated list of additional port numbers to treat as TLS endpoints (e.g., `12345,54321`). These are checked in addition to the built-in defaults (443, 8443, 9443, 2379, 5671, 6380, 9200) and any port named `https` or `https-*`. |
| `--scan-all-ports` | `TLS_COMPLIANCE_SCAN_ALL_PORTS` | bool | `false` | Scan all declared TCP container ports on pods, not just known TLS ports. Useful for discovering TLS on non-standard ports that the default heuristics miss. Increases scan time and may produce more `NoTLS` reports. HTTP health-probe ports are still skipped. |
| `--enumerate-ciphers` | _(none)_ | bool | `true` | Enumerate all supported cipher suites per TLS version. When enabled, the operator performs multiple handshakes to discover every cipher suite each TLS version accepts. Disable for faster scans if you only need the first negotiated cipher. |
| `--metrics-per-endpoint` | _(none)_ | bool | `true` | Emit per-endpoint Prometheus metrics (certificate expiry, TLS version support, PQC readiness, forward secrecy). Disable on large clusters (2000+ endpoints) to reduce metric cardinality and Prometheus memory usage. Aggregate metrics (`tls_compliance_endpoints_total`) are always emitted regardless of this setting. |

## Rate Limiting

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--rate-limit` | `TLS_COMPLIANCE_RATE_LIMIT` | float | `10` | Maximum TLS checks per second (token bucket rate). Controls how aggressively the operator probes endpoints. On large clusters, increase this alongside `--workers` for faster scans. |
| `--rate-burst` | `TLS_COMPLIANCE_RATE_BURST` | int | `20` | Token bucket burst size. Allows short bursts above the rate limit. Range: 1-1000. |
| `--namespace-rate-limits` | _(none)_ | string | `""` | Per-namespace TLS check rate limits. Format: `namespace=rate,...` (e.g., `production=2.0,staging=10.0`). Namespaces not listed use the global `--rate-limit`. Useful for limiting scan impact on sensitive namespaces while allowing faster scans elsewhere. |

## Namespace Filtering

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--include-namespaces` | `TLS_COMPLIANCE_INCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to exclusively monitor. When set, only endpoints in these namespaces are scanned. Overrides `--exclude-namespaces`. |
| `--exclude-namespaces` | `TLS_COMPLIANCE_EXCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to skip. Ignored if `--include-namespaces` is set. |

If neither flag is set, all namespaces are scanned.

## Report Retention

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--report-retention-days` | `TLS_COMPLIANCE_REPORT_RETENTION_DAYS` | int | `0` | Delete TLSComplianceReport CRs with no activity for this many days. Set to `0` (default) to disable retention and keep reports indefinitely. When enabled, the cleanup loop removes stale reports each cycle and increments the `tls_compliance_reports_ttl_deleted_total` metric. |

### Example

To automatically clean up reports older than 90 days:

```yaml
env:
- name: TLS_COMPLIANCE_REPORT_RETENTION_DAYS
  value: "90"
```

Or via CLI flag:

```yaml
args:
- --report-retention-days=90
```

## Certificate Monitoring

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--cert-expiry-warning-days` | `TLS_COMPLIANCE_CERT_EXPIRY_WARNING_DAYS` | int | `30` | Number of days before certificate expiry to emit a `CertificateExpiring` warning event. Range: 1-365. Set lower for environments with short-lived certificates (e.g., cert-manager with 90-day certs). |

## mTLS Probing

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--client-cert` | `TLS_COMPLIANCE_CLIENT_CERT` | string | `""` | Path to a PEM-encoded client certificate for mTLS endpoint probing. When configured alongside `--client-key`, the operator presents this certificate during TLS handshakes. This allows probing endpoints that require mutual TLS, which would otherwise report `MutualTLSRequired`. |
| `--client-key` | `TLS_COMPLIANCE_CLIENT_KEY` | string | `""` | Path to a PEM-encoded client private key for mTLS endpoint probing. Must be provided with `--client-cert`. |

## Retry Behavior

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--max-retries` | `TLS_COMPLIANCE_MAX_RETRIES` | int | `3` | Maximum number of retries for transient TLS check failures (Timeout, Unreachable). Range: 0-10. Set to 0 to disable retries entirely. Each retry uses exponential backoff. |
| `--retry-backoff` | `TLS_COMPLIANCE_RETRY_BACKOFF` | duration | `30s` | Base backoff duration between retries. Actual delay is `base * 2^attempt` (30s, 60s, 120s for the default). On clusters with many unreachable endpoints, increasing this reduces wasted checks. |
| `--max-backoff` | `TLS_COMPLIANCE_MAX_BACKOFF` | duration | `5m` | Maximum backoff duration between retries. Caps exponential growth so retries don't wait indefinitely. |

## OpenShift Integration

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--profile-refresh-interval` | `TLS_COMPLIANCE_PROFILE_REFRESH_INTERVAL` | duration | `5m` | How often to re-fetch OpenShift TLS security profile configuration (APIServer, IngressController, KubeletConfig). Only used when running on OpenShift. Ignored on vanilla Kubernetes. |

## Logging

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--log-format` | `TLS_COMPLIANCE_LOG_FORMAT` | string | `text` | Log output format. Use `text` for human-readable development logs or `json` for structured logs suitable for log aggregation pipelines (ELK, Splunk, CloudWatch). |

## CI/CD Integration

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--run-once` | `TLS_COMPLIANCE_RUN_ONCE` | bool | `false` | Perform a single full scan and exit. Exit code 0 = all compliant, 1 = non-compliant found, 2 = scan error. Automatically disables leader election, metrics, and health probes. See [CI Integration Guide](ci-integration.md) for examples. |
| `--output-format` | `TLS_COMPLIANCE_OUTPUT_FORMAT` | string | `""` | Write scan results in this format when using `--run-once`. Supported: `csv`, `json`, `yaml`, `junit`, `markdown`. Results go to stdout unless `--output-file` is set. |
| `--output-file` | `TLS_COMPLIANCE_OUTPUT_FILE` | string | `""` | Path to write scan results. Requires `--output-format`. |

## Infrastructure

These flags are standard controller-runtime/kubebuilder flags. They do not have
environment variable overrides.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--metrics-bind-address` | string | `0` | Address for the metrics endpoint. Use `:8443` for HTTPS, `:8080` for HTTP, or `0` to disable. |
| `--health-probe-bind-address` | string | `:8081` | Address for liveness and readiness probes (`/healthz` and `/readyz`). |
| `--leader-elect` | bool | `false` | Enable leader election for HA deployments. Only one replica processes events at a time. |
| `--metrics-secure` | bool | `true` | Serve metrics over HTTPS. Set to `false` for HTTP. |
| `--enable-http2` | bool | `false` | Enable HTTP/2 for metrics and webhook servers. Disabled by default to mitigate HTTP/2 rapid reset CVEs. |
| `--metrics-cert-path` | string | `""` | Directory containing the metrics server TLS certificate. |
| `--metrics-cert-name` | string | `tls.crt` | Filename of the metrics server certificate. |
| `--metrics-cert-key` | string | `tls.key` | Filename of the metrics server private key. |
| `--webhook-cert-path` | string | `""` | Directory containing the webhook server TLS certificate. |
| `--webhook-cert-name` | string | `tls.crt` | Filename of the webhook certificate. |
| `--webhook-cert-key` | string | `tls.key` | Filename of the webhook private key. |

## Examples

### Environment variables in a Deployment

```yaml
env:
- name: TLS_COMPLIANCE_SCAN_INTERVAL
  value: "30m"
- name: TLS_COMPLIANCE_WORKERS
  value: "10"
- name: TLS_COMPLIANCE_EXCLUDE_NAMESPACES
  value: "kube-system,openshift-monitoring"
- name: TLS_COMPLIANCE_CERT_EXPIRY_WARNING_DAYS
  value: "14"
- name: TLS_COMPLIANCE_EXTRA_TLS_PORTS
  value: "12345,54321"
- name: TLS_COMPLIANCE_SCAN_ALL_PORTS
  value: "true"
- name: TLS_COMPLIANCE_LOG_FORMAT
  value: "json"
```

### CLI flags in container args

```yaml
args:
- --scan-interval=30m
- --workers=10
- --exclude-namespaces=kube-system,openshift-monitoring
- --cert-expiry-warning-days=14
- --extra-tls-ports=12345,54321
- --scan-all-ports
- --log-format=json
- --leader-elect
```

## Per-Resource Annotations

These annotations can be added to any Service, Ingress, Route, or Pod to
control scanning behavior on a per-resource basis.

### Skip scanning

Add the `tls-compliance.telco.openshift.io/skip` annotation to exclude a
resource from TLS scanning entirely:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-internal-service
  annotations:
    tls-compliance.telco.openshift.io/skip: "true"
spec:
  ports:
  - port: 8443
```

The operator ignores any resource with this annotation set to `"true"`.

### Extra ports

Add the `tls-compliance.telco.openshift.io/extra-ports` annotation to scan
additional ports beyond what the operator auto-discovers:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: multi-port-service
  annotations:
    tls-compliance.telco.openshift.io/extra-ports: "9443,6443"
spec:
  ports:
  - port: 443
```

The annotation accepts a comma-separated list of port numbers (1-65535).
These ports are scanned in addition to the ports the operator discovers
from the resource spec.

## Resource Sizing

The default resource limits are configured for small-to-medium clusters
(up to ~500 TLS endpoints):

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 10m | 500m |
| Memory | 64Mi | 256Mi |

### Scaling Guidance

Memory usage scales with the number of endpoints being monitored and the
concurrency settings:

| Endpoints | Workers | Rate Limit | Recommended Memory Limit |
|-----------|---------|------------|-------------------------|
| < 500 | 5 | 10 | 256Mi (default) |
| 500-2000 | 10 | 20 | 512Mi |
| 2000+ | 20 | 50 | 1Gi |

Increasing `--workers` and `--rate-limit` will increase peak memory usage
since more TLS checks run concurrently. Monitor actual usage with:

```promql
container_memory_working_set_bytes{container="manager"}
```

### High-Memory Kustomize Overlay

For larger clusters, use the provided kustomize overlay:

```bash
kubectl kustomize config/overlays/high-memory/ | kubectl apply -f -
```

This sets memory limits to 512Mi and requests to 128Mi. Customize the overlay
values for your workload by editing
`config/overlays/high-memory/kustomization.yaml`.

---

Next: [Architecture](architecture.md)
