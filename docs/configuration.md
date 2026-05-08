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
| `--tls-check-timeout` | `TLS_COMPLIANCE_CHECK_TIMEOUT` | duration | `5s` | Timeout for each individual TLS connection attempt. The operator probes TLS 1.0, 1.1, 1.2, 1.3, and SSLv3 sequentially, so worst-case time per endpoint is roughly 5x this value. Increase on high-latency networks. |
| `--workers` | `TLS_COMPLIANCE_WORKERS` | int | `5` | Number of concurrent goroutines used during periodic scans. Range: 1-50. Higher values scan faster but use more CPU and network. This also controls `MaxConcurrentReconciles` for the controller work queue. |
| `--extra-tls-ports` | `TLS_COMPLIANCE_EXTRA_TLS_PORTS` | string | `""` | Comma-separated list of additional port numbers to treat as TLS endpoints (e.g., `12345,54321`). These are checked in addition to the built-in defaults (443, 8443, 9443, 2379, 5671, 6380, 9200) and any port named `https` or `https-*`. |

## Rate Limiting

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--rate-limit` | `TLS_COMPLIANCE_RATE_LIMIT` | float | `10` | Maximum TLS checks per second (token bucket rate). Controls how aggressively the operator probes endpoints. On large clusters, increase this alongside `--workers` for faster scans. |
| `--rate-burst` | `TLS_COMPLIANCE_RATE_BURST` | int | `20` | Token bucket burst size. Allows short bursts above the rate limit. Range: 1-1000. |

## Namespace Filtering

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--include-namespaces` | `TLS_COMPLIANCE_INCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to exclusively monitor. When set, only endpoints in these namespaces are scanned. Overrides `--exclude-namespaces`. |
| `--exclude-namespaces` | `TLS_COMPLIANCE_EXCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to skip. Ignored if `--include-namespaces` is set. |

If neither flag is set, all namespaces are scanned.

## Certificate Monitoring

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--cert-expiry-warning-days` | `TLS_COMPLIANCE_CERT_EXPIRY_WARNING_DAYS` | int | `30` | Number of days before certificate expiry to emit a `CertificateExpiring` warning event. Range: 1-365. Set lower for environments with short-lived certificates (e.g., cert-manager with 90-day certs). |

## Retry Behavior

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--max-retries` | `TLS_COMPLIANCE_MAX_RETRIES` | int | `3` | Maximum number of retries for transient TLS check failures (Timeout, Unreachable). Range: 0-10. Set to 0 to disable retries entirely. Each retry uses exponential backoff. |
| `--retry-backoff` | `TLS_COMPLIANCE_RETRY_BACKOFF` | duration | `30s` | Base backoff duration between retries. Actual delay is `base * 2^attempt` (30s, 60s, 120s for the default). On clusters with many unreachable endpoints, increasing this reduces wasted checks. |

## OpenShift Integration

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--profile-refresh-interval` | `TLS_COMPLIANCE_PROFILE_REFRESH_INTERVAL` | duration | `5m` | How often to re-fetch OpenShift TLS security profile configuration (APIServer, IngressController, KubeletConfig). Only used when running on OpenShift. Ignored on vanilla Kubernetes. |

## Logging

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--log-format` | `TLS_COMPLIANCE_LOG_FORMAT` | string | `text` | Log output format. Use `text` for human-readable development logs or `json` for structured logs suitable for log aggregation pipelines (ELK, Splunk, CloudWatch). |

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
- --log-format=json
- --leader-elect
```
