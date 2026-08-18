# Prometheus Metrics

All metrics use the `tls_compliance_` prefix.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tls_compliance_endpoints_total` | Gauge | `status` | Endpoints by compliance status |
| `tls_compliance_check_duration_seconds` | Histogram | - | TLS check duration |
| `tls_compliance_certificate_expiry_days` | Gauge | `host`, `port` | Days until certificate expiry. Requires `--metrics-per-endpoint`. |
| `tls_compliance_version_support` | Gauge | `host`, `port`, `version` | TLS version support (1=yes, 0=no). Requires `--metrics-per-endpoint`. |
| `tls_compliance_forward_secrecy` | Gauge | `host`, `port` | Forward secrecy support (1=all ciphers use ephemeral key exchange, 0=not). Requires `--metrics-per-endpoint`. |
| `tls_compliance_pqc_readiness` | Gauge | `host`, `port`, `readiness` | Post-quantum cryptography readiness (1=current status). One-hot across: PQCReady, TLS13Capable, LegacyTLS, NoPQC. Requires `--metrics-per-endpoint`. |
| `tls_compliance_reconcile_total` | Counter | `result` | Reconciliation attempts |
| `tls_compliance_reconcile_errors_total` | Counter | `source_kind`, `error_type` | Errors during resource reconciliation by source kind and error type |
| `tls_compliance_scan_cycle_duration_seconds` | Histogram | - | Full scan cycle duration |
| `tls_compliance_check_retries_total` | Counter | `reason` | TLS check retry attempts by failure reason |
| `tls_compliance_check_retries_exhausted_total` | Counter | - | Times TLS check retries were exhausted without success |
| `tls_compliance_scan_cycle_last_completed_timestamp` | Gauge | - | Unix timestamp of last successful scan cycle |
| `tls_compliance_cleanup_cycle_last_completed_timestamp` | Gauge | - | Unix timestamp of last successful cleanup cycle |
| `tls_compliance_reports_ttl_deleted_total` | Counter | - | TLSComplianceReports deleted by retention policy |
| `tls_compliance_scan_cycle_errors_total` | Counter | - | Total number of periodic scan cycle failures |
| `tls_compliance_fips_mode_enabled` | Gauge | - | Whether the cluster is running in FIPS mode (1=yes, 0=no) |

Per-endpoint series (`tls_compliance_certificate_expiry_days`, `tls_compliance_version_support`, `tls_compliance_forward_secrecy`, `tls_compliance_pqc_readiness`) are emitted only when `--metrics-per-endpoint=true`. That flag defaults to `false` because host/port labels create high cardinality on large clusters. Aggregate metrics such as `tls_compliance_endpoints_total` are always emitted.

## Example PromQL Queries

Queries that use `host`/`port` labels require `--metrics-per-endpoint=true`.

```promql
# Percentage of compliant endpoints
sum(tls_compliance_endpoints_total{status="Compliant"}) / sum(tls_compliance_endpoints_total) * 100

# Endpoints with certificates expiring within 7 days
tls_compliance_certificate_expiry_days < 7

# Endpoints still supporting TLS 1.0
tls_compliance_version_support{version="1.0"} == 1

# Average TLS check duration
histogram_quantile(0.95, rate(tls_compliance_check_duration_seconds_bucket[5m]))

# Endpoints without forward secrecy
tls_compliance_forward_secrecy == 0

# Count of PQC-ready endpoints
count(tls_compliance_pqc_readiness{readiness="PQCReady"} == 1)

# Retry rate by failure reason
rate(tls_compliance_check_retries_total[5m])

# Reports cleaned up by retention policy in the last 24h
increase(tls_compliance_reports_ttl_deleted_total[24h])

# Detect stalled scan loop (no completion in 2 hours)
time() - tls_compliance_scan_cycle_last_completed_timestamp > 7200

# Check if cluster is running in FIPS mode
tls_compliance_fips_mode_enabled == 1

# Alert on scan cycle errors
rate(tls_compliance_scan_cycle_errors_total[1h]) > 0
```

## Monitoring Setup

### Metrics Endpoint

The operator serves Prometheus metrics on its metrics endpoint (default `:8443`
over HTTPS). The metrics endpoint is TLS-secured by default. To configure TLS
certificates or switch to HTTP:

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `0` | Metrics endpoint address. Use `:8443` for HTTPS, `:8080` for HTTP, `0` to disable. |
| `--metrics-secure` | `true` | Serve metrics over HTTPS. Set to `false` for plain HTTP. |
| `--metrics-cert-path` | `""` | Directory containing the TLS certificate for the metrics server. |
| `--metrics-cert-name` | `tls.crt` | Certificate filename within the cert path. |
| `--metrics-cert-key` | `tls.key` | Private key filename within the cert path. |

See [Configuration > Infrastructure](configuration.md#infrastructure) for the
full list of infrastructure flags.

### ServiceMonitor (Prometheus Operator)

A `ServiceMonitor` is provided at `config/prometheus/monitor.yaml` for
Prometheus Operator-based clusters (including OpenShift). Apply it to enable
automatic scraping:

```bash
kubectl apply -f config/prometheus/monitor.yaml
```

The ServiceMonitor selects pods with the `control-plane: controller-manager`
label and scrapes the `https` port with TLS verification disabled (since the
operator uses a self-signed certificate by default). If your Prometheus is in
a different namespace, you may need a cross-namespace ServiceMonitor or adjust
your Prometheus configuration to discover it.

**Manual scrape config** (if not using Prometheus Operator):

```yaml
scrape_configs:
  - job_name: tls-compliance-operator
    scheme: https
    tls_config:
      insecure_skip_verify: true
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
            - tls-compliance-operator-system
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_label_control_plane]
        regex: controller-manager
        action: keep
      - source_labels: [__meta_kubernetes_endpoint_port_name]
        regex: https
        action: keep
```

### Alerting Rules

Pre-built alerting rules are provided at
`config/prometheus/alerting-rules.yaml`. Apply them to your cluster:

```bash
kubectl apply -f config/prometheus/alerting-rules.yaml
```

The following alerts are included. Certificate expiry alerts require `--metrics-per-endpoint=true`; the others use aggregate metrics that are always emitted.

| Alert | Severity | Condition | Description |
|-------|----------|-----------|-------------|
| `TLSEndpointNonCompliant` | warning | Non-compliant endpoints for > 1h | Endpoints only supporting TLS 1.0/1.1 |
| `TLSCertificateExpiringSoon` | warning | Certificate expires in < 30 days | Upcoming certificate expiration |
| `TLSCertificateExpired` | critical | Certificate expiry days <= 0 | Certificate has already expired |
| `TLSScanCycleSlow` | warning | p95 scan duration > 5 minutes | Scan cycles taking longer than expected |
| `TLSScanCycleStalled` | warning | No scan completion in 2 hours | Periodic scan loop may be stuck |
| `TLSCleanupCycleStalled` | warning | No cleanup in 10 minutes | Cleanup loop may be stuck |
| `TLSEndpointUnreachable` | info | Unreachable endpoints for > 24h | Persistent network connectivity issues |

### Grafana Dashboard

A pre-built Grafana dashboard is included at `config/grafana/dashboard.json`.
It provides panels for compliance status breakdown, certificate expiry,
TLS version support, scan performance, and retry activity. Certificate expiry,
TLS version, PQC, and forward secrecy panels require `--metrics-per-endpoint=true`.

**Import via Grafana UI:**

1. Open Grafana and navigate to **Dashboards > Import**
2. Click **Upload JSON file** and select `config/grafana/dashboard.json`
3. Select your Prometheus datasource
4. Click **Import**

**Import via ConfigMap** (for sidecar-provisioned Grafana):

```bash
kubectl create configmap tls-compliance-dashboard \
  --from-file=dashboard.json=config/grafana/dashboard.json \
  -n monitoring

kubectl label configmap tls-compliance-dashboard \
  grafana_dashboard=1 \
  -n monitoring
```

Adjust the namespace and label to match your Grafana sidecar configuration.

---

Next: [Custom Targets](custom-targets.md)
