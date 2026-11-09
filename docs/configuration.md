# Configuration Reference

The tls-compliance-operator is configured via command-line flags. Every flag
can also be set via an environment variable, which is useful when deploying
with kustomize overlays where modifying container args is inconvenient.

**Precedence:** CLI flag > environment variable > default value.

If a flag is set on the command line, its environment variable is ignored.

## Scanning

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--scan-interval` | `TLS_COMPLIANCE_SCAN_INTERVAL` | duration | `1h` | How often the operator re-checks all known TLS endpoints. Each cycle scans every Service, Ingress, Route, and Pod endpoint. Shorter intervals give faster detection but increase API server and network load. Must be greater than `0`; zero or negative values are rejected at startup. |
| `--cleanup-interval` | `TLS_COMPLIANCE_CLEANUP_INTERVAL` | duration | `5m` | How often the operator removes TLSComplianceReport CRs whose source resource (Service, Ingress, Route) has been deleted. Must be greater than `0`; zero or negative values are rejected at startup. |
| `--tls-check-timeout` | `TLS_COMPLIANCE_CHECK_TIMEOUT` | duration | `5s` | Timeout for each individual TLS connection attempt. The operator probes all TLS versions (1.0, 1.1, 1.2, 1.3, SSLv3) in parallel, so worst-case time per endpoint is roughly 1x this value plus a small overhead for the ML-KEM active probe. Increase on high-latency networks. |
| `--workers` | `TLS_COMPLIANCE_WORKERS` | int | `5` | Number of concurrent goroutines used during periodic scans. Range: 1-50. Higher values scan faster but use more CPU and network. This also sets `MaxConcurrentReconciles` for each per-kind controller (Service, Ingress, Route, each Gateway API kind, Target, Report); the TLS check worker pool they share stays at this size. |
| `--extra-tls-ports` | `TLS_COMPLIANCE_EXTRA_TLS_PORTS` | string | `""` | Comma-separated list of additional port numbers to treat as TLS endpoints (e.g., `12345,54321`). These are checked in addition to the built-in defaults (443, 2379, 2380, 5443, 5671, 6380, 6443, 7443, 8443, 9091, 9092, 9093, 9100, 9200, 9443, 10250, 10257, 10259) and any port named `https` or `https-*`. |
| `--scan-all-ports` | `TLS_COMPLIANCE_SCAN_ALL_PORTS` | bool | `false` | Scan all declared TCP container ports on pods, not just known TLS ports. Useful for discovering TLS on non-standard ports that the default heuristics miss. Increases scan time and may produce more `NoTLS` reports. HTTP health-probe ports are still skipped. |
| `--enumerate-ciphers` | `TLS_COMPLIANCE_ENUMERATE_CIPHERS` | bool | `true` | Enumerate all supported cipher suites per TLS version. When enabled, the operator performs multiple handshakes to discover every cipher suite each TLS version accepts. Disable for faster scans if you only need the first negotiated cipher. |
| `--detect-cipher-preference` | `TLS_COMPLIANCE_DETECT_CIPHER_PREFERENCE` | bool | `false` | Detect whether TLS 1.2 endpoints prefer their own cipher order. Performs two extra handshakes offering the first two discovered suites in opposite orders; requires `--enumerate-ciphers` to have found at least two suites. The result is recorded as `status.serverPrefersOwnCiphers` on the report. |
| `--metrics-per-endpoint` | `TLS_COMPLIANCE_METRICS_PER_ENDPOINT` | bool | `false` | Emit per-endpoint Prometheus metrics (certificate expiry, TLS version support, PQC readiness, forward secrecy). Leave off on large clusters (2000+ endpoints) to avoid high metric cardinality and Prometheus memory usage. Aggregate metrics (`tls_compliance_endpoints_total`) are always emitted regardless of this setting. |
| `--starttls-ports` | `TLS_COMPLIANCE_STARTTLS_PORTS` | string | `""` | Override the built-in STARTTLS port map: `proto=port[:port][,proto=port...]`. Supported protocols: `smtp`, `imap`, `ldap`, `postgres`, `mysql`, `pop3`, `lmtp`, `xmpp`, `xmpp-server`, `nntp`, `sieve`, `ftp`. An entry whose port repeats later overrides the earlier one. Unknown protocols, malformed entries, and ports outside 1-65535 fail startup. |

STARTTLS is attempted only after the plaintext probes classify an endpoint as
`NoTLS` or `Unreachable`, and the per-probe context deadline still applies to
the cleartext exchange. Built-in STARTTLS ports: SMTP 25/587, IMAP 143, LDAP
389, PostgreSQL 5432, MySQL/MariaDB 3306/3307, POP3 110, LMTP 24, XMPP 5222,
XMPP-server 5269, NNTP 119, Sieve 4190, FTP 21. Telnet has no standardized
STARTTLS negotiation and is not scanned.

The `kubectl tlsreport` plugin only reads `TLSComplianceReport`s, so this flag
applies to the manager only.

### Scan Window

Restrict periodic scans to a daily time window. Outside the window the periodic
scan cycle is skipped (new and changed resources are still checked promptly).
The window is `[start, end)` in the configured timezone; overnight windows
(e.g. `22:00`–`02:00`) are supported.
When a periodic tick is skipped because it falls outside the window, one
catch-up scan runs as soon as the window next opens, and later ticks are
realigned to that time. This keeps an interval longer than the window (e.g.
`--scan-interval=24h` with a 4-hour window) from starving; the operator logs a
warning at startup for that combination.

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--scan-window-start` | `TLS_COMPLIANCE_SCAN_WINDOW_START` | string | `""` | Start of the daily scan window in `HH:MM` format. Must be set together with `--scan-window-end` and differ from it. Empty (default) means no window restriction. |
| `--scan-window-end` | `TLS_COMPLIANCE_SCAN_WINDOW_END` | string | `""` | End of the daily scan window in `HH:MM` format. Must be set together with `--scan-window-start`. Empty (default) means no window restriction. |
| `--scan-window-timezone` | `TLS_COMPLIANCE_SCAN_WINDOW_TIMEZONE` | string | `UTC` | IANA timezone used to interpret the window boundaries (e.g. `America/New_York`). |

The operator exits at startup if only one of `--scan-window-start`/`--scan-window-end`
is set, if the two times are equal, or if a time is not valid `HH:MM`.

Example: scan only between 22:00 and 02:00 US Eastern:

```yaml
args:
- --scan-window-start=22:00
- --scan-window-end=02:00
- --scan-window-timezone=America/New_York
```

## Rate Limiting

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--rate-limit` | `TLS_COMPLIANCE_RATE_LIMIT` | float | `10` | Maximum TLS checks per second (token bucket rate). Controls how aggressively the operator probes endpoints. On large clusters, increase this alongside `--workers` for faster scans. |
| `--rate-burst` | `TLS_COMPLIANCE_RATE_BURST` | int | `20` | Token bucket burst size. Allows short bursts above the rate limit. Range: 1-1000. |
| `--namespace-rate-limits` | `TLS_COMPLIANCE_NAMESPACE_RATE_LIMITS` | string | `""` | Per-namespace TLS check rate limits. Format: `namespace=rate,...` (e.g., `production=2.0,staging=10.0`). Namespaces not listed use the global `--rate-limit`. Useful for limiting scan impact on sensitive namespaces while allowing faster scans elsewhere. |

## Namespace Filtering

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--include-namespaces` | `TLS_COMPLIANCE_INCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to exclusively monitor. When set, only endpoints in these namespaces are scanned. Overrides `--exclude-namespaces`. |
| `--exclude-namespaces` | `TLS_COMPLIANCE_EXCLUDE_NAMESPACES` | string | `""` | Comma-separated list of namespaces to skip. Ignored if `--include-namespaces` is set. |

If neither flag is set, all namespaces are scanned.

The filter also applies to reports that already exist. Changing either flag
takes effect on restart: the periodic scan stops probing reports from filtered
namespaces, and the next cleanup cycle deletes them. `TLSComplianceTarget`
reports are cluster-scoped and are never removed by the namespace filter.

`TLSComplianceTarget` objects are reconciled regardless of the filter. The
`tls-compliance.telco.openshift.io/rescan` annotation is honored on Target reports and
on reports from namespaces inside the filter. It is ignored on reports from
filtered namespaces, because cleanup deletes those reports. The operator logs
the skip and records a `RescanSkipped` Warning event on the report.

In `--run-once` mode, cleanup does not run, so the JUnit/JSON output and the
exit code include only reports inside the filter. Reports left from an earlier
unfiltered run are not counted. The `tls_compliance_endpoints_total` gauge also
counts only reports inside the filter.

Keep in mind:

- The filter matches the namespace of the object that exposes an endpoint, not
  the namespace of the workload behind it. An Ingress, Route or HTTPRoute in an
  included namespace is still probed even when its router or Gateway runs in a
  filtered namespace.
- The filter limits what the operator scans. It is not an access-control
  boundary: the operator still watches and caches Services, Pods and the other
  source kinds in every namespace, using its cluster-wide RBAC.
- A flag value with no namespace names in it (for example `" , "`) is ignored
  with a startup warning, and all namespaces are scanned.

## Report Retention

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--report-retention-days` | `TLS_COMPLIANCE_REPORT_RETENTION_DAYS` | int | `0` | Delete TLSComplianceReport CRs with no activity for this many days. Set to `0` (default) to disable retention and keep reports indefinitely. When enabled, the cleanup loop removes stale reports each cycle and increments the `tls_compliance_reports_ttl_deleted_total` metric. |
| `--max-history-entries` | `TLS_COMPLIANCE_MAX_HISTORY_ENTRIES` | int | `10` | Maximum number of historical scan results to keep per TLSComplianceReport. Range: 1-100. Older entries are pruned when the limit is exceeded. History is only appended when compliance status, cipher grade, certificate fingerprint, or TLS version support changes. |

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

## Certificate Trust Verification

TLS probing is non-verifying by default: the operator reports what an endpoint
supports, so `InsecureSkipVerify` is intentional. Setting `--ca-cert` adds a
second, opt-in check.

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--ca-cert` | `TLS_COMPLIANCE_CA_CERT` | string | `""` | Path to a PEM-encoded CA bundle. When set, every successful check re-handshakes with the endpoint and verifies the presented chain (including the hostname) against this bundle. The verdict is recorded as `status.certificateInfo.trusted` and, on failure, `status.certificateInfo.trustError`. The bundle must contain at least one PEM certificate or the manager exits at startup. |

Trust verification never changes `ComplianceStatus`: an untrusted chain is
recorded on the certificate, not treated as a TLS compliance failure. Alert on
`trusted: "false"` in the report or via the exported reports.

## Retry Behavior

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--max-retries` | `TLS_COMPLIANCE_MAX_RETRIES` | int | `3` | Maximum number of retries for transient TLS check failures (Timeout, Closed, Unreachable, Filtered). Range: 0-10. Set to 0 to disable retries entirely. Each retry uses exponential backoff. Retries apply only to checks triggered by resource events and the rescan annotation. The periodic scan probes each endpoint once and lets the next interval act as the retry. A retry stops early if its report is deleted during the backoff. |
| `--retry-backoff` | `TLS_COMPLIANCE_RETRY_BACKOFF` | duration | `30s` | Base backoff duration between retries. Actual delay is `base * 2^attempt` (30s, 60s, 120s for the default). On clusters with many unreachable endpoints, increasing this reduces wasted checks. |
| `--max-backoff` | `TLS_COMPLIANCE_MAX_BACKOFF` | duration | `5m` | Maximum backoff duration between retries. Caps exponential growth so retries don't wait indefinitely. |

## Webhook Notifications

Kubernetes Events are visible only inside the cluster. Setting `--notify-webhook`
also POSTs a JSON payload to one or more endpoints whenever an endpoint's
compliance status or PQC readiness changes.

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--notify-webhook` | `TLS_COMPLIANCE_NOTIFY_WEBHOOK` | string (repeatable) | `""` | Absolute http(s) URL to POST status transitions to. Repeat the flag, or give a comma-separated list in one flag or env var. Invalid URLs fail startup. |
| `--notify-timeout` | `TLS_COMPLIANCE_NOTIFY_TIMEOUT` | duration | `5s` | Timeout for one delivery attempt. Must be greater than zero. |
| `--notify-retries` | `TLS_COMPLIANCE_NOTIFY_RETRIES` | int | `2` | Extra attempts after a failed delivery, with linear backoff. Range: 0-10. |

The payload is:

```json
{
  "reportName": "web-443-abcd1234",
  "namespace": "prod",
  "host": "web.example.com",
  "port": 443,
  "oldStatus": "Compliant",
  "newStatus": "NonCompliant",
  "oldPQCReadiness": "PQCReady",
  "newPQCReadiness": "TLS13Capable",
  "timestamp": "2026-11-06T20:00:00Z"
}
```

Delivery is best effort and runs off the reconcile path: a slow or unavailable
receiver never blocks a scan or causes a reconcile error. An endpoint's first
measurement (`""` or `Pending` old status) is not a transition, so enabling
webhooks does not produce a burst for every existing report. Every webhook
delivery is counted in `tls_compliance_notifications_total{result}`.

## OpenShift Integration

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--profile-refresh-interval` | `TLS_COMPLIANCE_PROFILE_REFRESH_INTERVAL` | duration | `5m` | How often to re-fetch OpenShift TLS security profile configuration (APIServer, IngressController, KubeletConfig). Only used when running on OpenShift. Ignored on vanilla Kubernetes. Must be greater than `0`; zero or negative values are rejected at startup. |
| `--tls-profile-type` | `TLS_COMPLIANCE_TLS_PROFILE_TYPE` | string | `""` | Force a built-in TLS security profile (`Old`, `Intermediate`, `Modern`) for every component and skip reading OpenShift config. Fails fast on any other value. See [HyperShift](#hypershift). |
| `--custom-profile` | `TLS_COMPLIANCE_CUSTOM_PROFILE` | string | `""` | Name of a `TLSSecurityProfile` CR to evaluate every endpoint against, in addition to the component profiles. See [Custom TLS Profiles](#custom-tls-profiles). |

### Custom TLS Profiles

A `TLSSecurityProfile` declares a cluster-defined profile — a minimum TLS
version plus optional allowed ciphers and key exchange groups — beyond the
built-in `Old`, `Intermediate`, and `Modern` profiles:

```yaml
apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSSecurityProfile
metadata:
  name: strict-13
spec:
  minTLSVersion: VersionTLS13
  ciphers:
    - TLS_AES_128_GCM_SHA256
    - TLS_AES_256_GCM_SHA384
  groups:
    - X25519
    - secp256r1
```

Select it at operator startup:

```bash
--custom-profile=strict-13
```

Every checked endpoint is then also evaluated against it, and the verdict is
recorded on the report:

```bash
kubectl get tlscompliancereport <name> -o jsonpath='{.status.customProfileCompliance}'
# {"compliant":false,"groupsCompliant":true,"minTLSVersionMet":false,"profileType":"Custom"}
```

`minTLSVersionMet` means the endpoint supports no TLS version below the
profile's minimum. The profile is read once at startup, so a change to the CR
requires an operator restart. The built-in component profiles continue to be
evaluated independently. The operator needs `get` on `tlssecurityprofiles`.

### HyperShift

On HyperShift, the hosted control plane's `APIServer` CR lives in the management
cluster's namespace, not in the guest cluster's API, so the operator cannot read
the real profile. Without an override it detects no `config.openshift.io` API and
skips profile compliance entirely.

Set `--tls-profile-type` to the profile the hosted control plane actually uses:

```yaml
args:
  - --tls-profile-type=Intermediate
```

The named built-in profile is applied to the APIServer, IngressController, and
KubeletConfig components alike. No cluster reads or refresh loop are started,
and the selected source is recorded on every report:

```bash
kubectl get tlscompliancereports -o jsonpath='{.items[0].status.tlsProfileSource}'
# Override
```

`kubectl tlsreport summary` shows the same value as `Profile Source:`.

## Logging

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--log-format` | `TLS_COMPLIANCE_LOG_FORMAT` | string | `text` | Log output format. Use `text` for human-readable development logs or `json` for structured logs suitable for log aggregation pipelines (ELK, Splunk, CloudWatch). |

## CI/CD Integration

| Flag | Env Var | Type | Default | Description |
|------|---------|------|---------|-------------|
| `--run-once` | `TLS_COMPLIANCE_RUN_ONCE` | bool | `false` | Perform a single full scan and exit. Exit code 0 = all compliant, 1 = non-compliant found, 2 = scan error. Automatically disables leader election, metrics, and health probes. See [CI Integration Guide](ci-integration.md) for examples. |
| `--require-pqc` | `TLS_COMPLIANCE_REQUIRE_PQC` | bool | `false` | With `--run-once`, exit 1 unless every scannable endpoint is `PQCReady` (TLS 1.3 with hybrid ML-KEM). Unscannable endpoints are skipped and counted, never silently passed. Ignored outside run-once mode. See [PQC-Only Gate](pqc-mlkem.md#pqc-only-gate). |
| `--output-format` | `TLS_COMPLIANCE_OUTPUT_FORMAT` | string | `""` | Write scan results in this format when using `--run-once`. Supported: `csv`, `json`, `yaml`, `junit`, `markdown`, `html`, `sarif`. Results go to stdout unless `--output-file` is set. |
| `--output-file` | `TLS_COMPLIANCE_OUTPUT_FILE` | string | `""` | Path to write scan results. Requires `--output-format`. |
| `--shutdown-drain-timeout` | `TLS_COMPLIANCE_SHUTDOWN_DRAIN_TIMEOUT` | duration | `30s` | How long to wait for in-flight TLS checks to complete on shutdown before forcing exit. |

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
from the resource spec. Invalid tokens (non-numeric or out of range) are
skipped and logged so the rest of the list still applies. Empty or missing
annotations are ignored.

## Resource Sizing

The default resource limits are configured for small-to-medium clusters
(up to ~500 TLS endpoints):

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 10m | 500m |
| Memory | 128Mi | 512Mi |

The Deployment also sets `GOMAXPROCS=1` and `GOMEMLIMIT=460MiB` so the Go
runtime stays within the container memory limit.

### Scaling Guidance

Memory usage scales with the number of endpoints being monitored and the
concurrency settings:

| Endpoints | Workers | Rate Limit | Recommended Memory Limit |
|-----------|---------|------------|-------------------------|
| < 500 | 5 | 10 | 512Mi (default) |
| 500-2000 | 10 | 20 | 1Gi |
| 2000+ | 20 | 50 | 2Gi |

Increasing `--workers` and `--rate-limit` will increase peak memory usage
since more TLS checks run concurrently. Monitor actual usage with:

```promql
container_memory_working_set_bytes{container="manager"}
```

### Kustomize Overlays

```bash
# Larger clusters (edit values in the overlay as needed)
kubectl kustomize config/overlays/high-memory/ | kubectl apply -f -

# Constrained clusters
kubectl kustomize config/overlays/low-resource/ | kubectl apply -f -

# Three replicas with leader election (memory matches the default)
kubectl kustomize config/overlays/high-availability/ | kubectl apply -f -
```

`config/overlays/high-memory/` currently sets the same 128Mi request / 512Mi
limit as the default Deployment. Raise those values (and `GOMEMLIMIT`) in
`config/overlays/high-memory/kustomization.yaml` for larger workloads.
`config/overlays/low-resource/` requests 5m/32Mi and limits 250m/128Mi.

---

Next: [Architecture](architecture.md)
