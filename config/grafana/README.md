# Grafana Dashboard

Pre-built Grafana dashboard for monitoring the TLS Compliance Operator.
Import `dashboard.json` from the **repository root** (paths below assume that).

Certificate expiry, TLS version, PQC, and forward secrecy panels require
`--metrics-per-endpoint=true`.

## Panels

- **Compliance Status Breakdown** — pie chart of endpoints by compliance status
- **Certificate Expiry (Days Remaining)** — table sorted by days until expiry
- **TLS Version Support Matrix** — TLS version support per endpoint
- **PQC Readiness Breakdown** — post-quantum readiness counts
- **Forward Secrecy Status** — endpoints with and without forward secrecy
- **FIPS Mode** — cluster FIPS indicator
- **Scan Cycle Duration** — p50/p95/p99 of full scan cycles
- **Individual Check Duration** — p50/p95/p99 of individual TLS checks
- **Worker Pool Utilization** — in-use worker slots
- **Reconciliation Rate** — reconciliation attempts by result
- **Retry Activity** — retries and exhausted retries
- **Reconcile Error Breakdown** — errors by source kind
- **Retention Activity (TTL Deleted)** — reports removed by retention
- **Reconciliation Latency by Resource Type**
- **TLS Check Errors by Reason**
- **Endpoints by Status** — counts per compliance status
- **Last Healthy Scan** — time since last completed scan cycle
- **Endpoint Discovery Rate** — newly discovered endpoints

## Prerequisites

- Prometheus scraping the operator's metrics endpoint
- The `ServiceMonitor` from `config/prometheus/` applied (or equivalent scrape config)

## Import via Grafana UI

1. Open Grafana and navigate to **Dashboards > Import**
2. Click **Upload JSON file** and select `config/grafana/dashboard.json`
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
