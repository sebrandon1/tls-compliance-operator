# Prometheus Metrics

All metrics use the `tls_compliance_` prefix.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tls_compliance_endpoints_total` | Gauge | `status` | Endpoints by compliance status |
| `tls_compliance_check_duration_seconds` | Histogram | - | TLS check duration |
| `tls_compliance_certificate_expiry_days` | Gauge | `host`, `port` | Days until certificate expiry |
| `tls_compliance_version_support` | Gauge | `host`, `port`, `version` | TLS version support (1=yes, 0=no) |
| `tls_compliance_reconcile_total` | Counter | `result` | Reconciliation attempts |
| `tls_compliance_scan_cycle_duration_seconds` | Histogram | - | Full scan cycle duration |
| `tls_compliance_scan_cycle_last_completed_timestamp` | Gauge | - | Unix timestamp of last successful scan cycle |
| `tls_compliance_cleanup_cycle_last_completed_timestamp` | Gauge | - | Unix timestamp of last successful cleanup cycle |

## Example PromQL Queries

```promql
# Percentage of compliant endpoints
sum(tls_compliance_endpoints_total{status="Compliant"}) / sum(tls_compliance_endpoints_total) * 100

# Endpoints with certificates expiring within 7 days
tls_compliance_certificate_expiry_days < 7

# Endpoints still supporting TLS 1.0
tls_compliance_version_support{version="1.0"} == 1

# Average TLS check duration
histogram_quantile(0.95, rate(tls_compliance_check_duration_seconds_bucket[5m]))

# Detect stalled scan loop (no completion in 2 hours)
time() - tls_compliance_scan_cycle_last_completed_timestamp > 7200
```

## ServiceMonitor

A `ServiceMonitor` is provided at `config/prometheus/monitor.yaml` for
Prometheus Operator-based clusters. Apply it to enable automatic scraping:

```bash
kubectl apply -f config/prometheus/monitor.yaml
```

## Alerting Rules

Pre-built alerting rules are at `config/prometheus/alerting-rules.yaml`:

```bash
kubectl apply -f config/prometheus/alerting-rules.yaml
```

## Grafana Dashboard

Import the dashboard from `config/grafana/dashboard.json` into your Grafana
instance for a visual overview of TLS compliance across the cluster.

---

Next: [Custom Targets](custom-targets.md)
