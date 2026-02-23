# Grafana Dashboard

Pre-built Grafana dashboard for monitoring the TLS Compliance Operator.

## Panels

- **Compliance Status Breakdown** - Pie chart of endpoints by compliance status
- **Certificate Expiry** - Table sorted by days until certificate expiry
- **TLS Version Support Matrix** - Table showing TLS version support per endpoint
- **Scan Cycle Duration** - p50/p95/p99 latency of full scan cycles
- **Individual Check Duration** - p50/p95/p99 latency of individual TLS checks
- **Reconciliation Rate** - Rate of reconciliation attempts by result
- **Retry Activity** - Rate of retries and exhausted retries
- **Endpoints by Status** - Stat panel with endpoint counts per status

## Prerequisites

- Prometheus scraping the operator's metrics endpoint
- The `ServiceMonitor` from `config/prometheus/` applied (or equivalent scrape config)

## Import via Grafana UI

1. Open Grafana and navigate to **Dashboards > Import**
2. Click **Upload JSON file** and select `dashboard.json`
3. Select your Prometheus datasource
4. Click **Import**

## Import via ConfigMap (Kubernetes)

If your Grafana instance is configured with sidecar dashboard provisioning
(common with the `grafana` Helm chart), create a ConfigMap:

```bash
kubectl create configmap tls-compliance-dashboard \
  --from-file=dashboard.json=config/grafana/dashboard.json \
  -n monitoring

kubectl label configmap tls-compliance-dashboard \
  grafana_dashboard=1 \
  -n monitoring
```

Adjust the namespace (`monitoring`) and label (`grafana_dashboard=1`) to match
your Grafana sidecar configuration.
