# TLS Compliance Operator

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

Continuously monitor all TLS endpoints in your Kubernetes or OpenShift cluster
for TLS version compliance, certificate health, and security posture.

## Overview

The TLS Compliance Operator is a Kubernetes operator that watches Services,
Ingresses, OpenShift Routes, and Pods to discover TLS endpoints, then probes
each endpoint to determine which TLS versions it supports. It creates
`TLSComplianceReport` custom resources with compliance status, supported TLS
versions, cipher suites, and certificate details.

**Use cases:**
- Enforce TLS 1.3 adoption across your cluster
- Detect endpoints still accepting TLS 1.0/1.1
- Monitor certificate expiration across all services
- Audit TLS configuration for compliance requirements

## Key Features

- **Automatic Discovery**: Watches Services (ports 443, 8443, https-*), Ingresses with TLS, OpenShift Routes, and Pods with TLS container ports
- **Pod IP Scanning**: Periodically scans all pod container ports for TLS endpoints, including hostNetwork pods exposing TLS on node interfaces
- **TLS Version Detection**: Probes each endpoint for TLS 1.0, 1.1, 1.2, and 1.3 support
- **Compliance Classification**: Categorizes endpoints as Compliant, NonCompliant, Warning, or Error
- **Certificate Tracking**: Reports issuer, subject, DNS names, expiration, and days until expiry
- **Cipher Suite Reporting**: Records negotiated cipher suites per TLS version
- **OpenShift Support**: Automatically detects and monitors OpenShift Routes when available
- **Prometheus Metrics**: Exposes compliance status, certificate expiry, and TLS version support
- **Kubernetes Events**: Emits events for non-compliance, status changes, and certificate warnings
- **Rate Limiting**: Configurable rate limiting for TLS endpoint checks
- **Cipher Strength Grading**: A-F grades for negotiated cipher suites
- **OpenShift TLS Profile Compliance**: Checks endpoints against APIServer, IngressController, and KubeletConfig TLS security profiles
- **Arbitrary Target Scanning**: Scan any host:port via `TLSComplianceTarget` CRD
- **Report Export**: CSV and JUnit XML export via `kubectl-tlsreport` plugin
- **Worker Pool**: Configurable concurrent workers for periodic scans
- **Post-Quantum Readiness**: Detects post-quantum key exchange algorithms (e.g. X25519MLKEM768)

## Quick Deploy

Deploy directly to your cluster with a single command (no clone required):

```bash
kubectl apply -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

To deploy a specific version:

```bash
kubectl apply -f https://github.com/sebrandon1/tls-compliance-operator/releases/download/v0.0.1/install.yaml
```

To uninstall:

```bash
kubectl delete -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

## Quick Start

### Deploy from Source

```bash
# Build and push to your registry
make docker-build docker-push IMG=quay.io/bapalm/tls-compliance-operator:latest

# Install CRDs and deploy
make install
make deploy IMG=quay.io/bapalm/tls-compliance-operator:latest
```

### Or Generate Install Manifest

```bash
make build-installer IMG=quay.io/bapalm/tls-compliance-operator:latest
kubectl apply -f dist/install.yaml
```

## Guides

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Deploy to your cluster in one command |
| [Viewing Reports](docs/viewing-reports.md) | Understand compliance status, cipher grades, and certificate info |
| [Custom Targets](docs/custom-targets.md) | Scan arbitrary external hosts with `TLSComplianceTarget` |
| [Exporting Reports](docs/exporting-reports.md) | CSV, JSON, and JUnit XML export for CI/CD |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and how to fix them |

## Architecture

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

**Flow:**
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

## Usage

Once deployed, the operator automatically discovers TLS endpoints and creates
`TLSComplianceReport` resources.

### View All TLS Compliance Reports

```bash
kubectl get tlsreport

# Example output:
# NAME                                    HOST                                    PORT   SOURCE    COMPLIANCE     TLS1.3   TLS1.2   TLS1.0   CERT-EXPIRY   AGE
# my-service-443-a1b2c3d4                 my-service.default                      443    Service   Compliant      true     true     false    29d           5m
# api-ingress-443-e5f6g7h8                api.example.com                         443    Ingress   NonCompliant   true     true     true     180d          5m
# 10-244-1-5-8443-f1e2d3c4                10.244.1.5                              8443   Pod       Compliant      true     true     false    365d          5m
# legacy-app-8443-i9j0k1l2                legacy.default                          8443   Service   Warning        false    true     false    7d            5m
```

### View Detailed Report

```bash
kubectl describe tlsreport my-service-443-a1b2c3d4
```

### Find Non-Compliant Endpoints

```bash
kubectl get tlsreport -o json | jq '.items[] | select(.status.complianceStatus == "NonCompliant") | .metadata.name'
```

### Find hostNetwork Pod Endpoints

```bash
kubectl get tlsreport -l tls-compliance.telco.openshift.io/host-network=true
```

### Find Endpoints with Expiring Certificates

```bash
kubectl get tlsreport -o json | jq '.items[] | select(.status.certificateInfo.daysUntilExpiry < 30) | {name: .metadata.name, host: .spec.host, days: .status.certificateInfo.daysUntilExpiry}'
```

## Configuration

The operator accepts the following command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--scan-interval` | `1h` | Interval for periodic full rescans |
| `--cleanup-interval` | `5m` | Interval for removing stale CRs |
| `--tls-check-timeout` | `5s` | Timeout per TLS connection attempt |
| `--rate-limit` | `10.0` | TLS checks per second |
| `--rate-burst` | `20` | Rate limiter burst size |
| `--include-namespaces` | `""` | Comma-separated namespaces to exclusively monitor (overrides exclude) |
| `--exclude-namespaces` | `""` | Comma-separated namespaces to skip |
| `--cert-expiry-warning-days` | `30` | Days before expiry to emit warnings |
| `--workers` | `5` | Concurrent workers for periodic scans (1-50) |
| `--profile-refresh-interval` | `5m` | Refresh interval for OpenShift TLS security profiles |
| `--metrics-bind-address` | `0` | Metrics endpoint bind address |
| `--health-probe-bind-address` | `:8081` | Health probe bind address |
| `--leader-elect` | `false` | Enable leader election for HA |

### Environment Variables

All configuration flags can also be set via environment variables. This is
useful when deploying via Helm charts or kustomize overlays where modifying
container args is inconvenient.

**Precedence:** CLI flag > environment variable > default value.

| Environment Variable | Flag | Default |
|---------------------|------|---------|
| `TLS_COMPLIANCE_SCAN_INTERVAL` | `--scan-interval` | `1h` |
| `TLS_COMPLIANCE_CHECK_TIMEOUT` | `--tls-check-timeout` | `5s` |
| `TLS_COMPLIANCE_RATE_LIMIT` | `--rate-limit` | `10` |
| `TLS_COMPLIANCE_WORKERS` | `--workers` | `5` |
| `TLS_COMPLIANCE_EXCLUDE_NAMESPACES` | `--exclude-namespaces` | `""` |

Example: set scan interval via environment variable in a Deployment:

```yaml
env:
- name: TLS_COMPLIANCE_SCAN_INTERVAL
  value: "30m"
- name: TLS_COMPLIANCE_WORKERS
  value: "10"
```

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

## Prometheus Metrics

All metrics use the `tls_compliance_` prefix.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tls_compliance_endpoints_total` | Gauge | `status` | Endpoints by compliance status |
| `tls_compliance_check_duration_seconds` | Histogram | - | TLS check duration |
| `tls_compliance_certificate_expiry_days` | Gauge | `host`, `port` | Days until certificate expiry |
| `tls_compliance_version_support` | Gauge | `host`, `port`, `version` | TLS version support (1=yes, 0=no) |
| `tls_compliance_reconcile_total` | Counter | `result` | Reconciliation attempts |
| `tls_compliance_scan_cycle_duration_seconds` | Histogram | - | Full scan cycle duration |

### Example PromQL Queries

```promql
# Percentage of compliant endpoints
sum(tls_compliance_endpoints_total{status="Compliant"}) / sum(tls_compliance_endpoints_total) * 100

# Endpoints with certificates expiring within 7 days
tls_compliance_certificate_expiry_days < 7

# Endpoints still supporting TLS 1.0
tls_compliance_version_support{version="1.0"} == 1

# Average TLS check duration
histogram_quantile(0.95, rate(tls_compliance_check_duration_seconds_bucket[5m]))
```

## Kubernetes Events

The operator emits the following events on `TLSComplianceReport` resources:

| Event | Type | Description |
|-------|------|-------------|
| `TLSNonCompliant` | Warning | TLS 1.0 or 1.1 detected |
| `ComplianceChanged` | Warning | Compliance status changed |
| `CertificateExpiring` | Warning | Certificate expires within configured threshold |
| `CertificateExpired` | Warning | Certificate has expired |
| `EndpointDiscovered` | Normal | New TLS endpoint discovered |

## Feature Comparison: tls-compliance-operator vs openshift/tls-scanner

The [openshift/tls-scanner](https://github.com/openshift/tls-scanner) is a batch Job-based TLS auditing tool for OpenShift/Kubernetes. This operator is independently developed but inspired by the scanner's categorization model. The tables below summarize shared features, unique capabilities, and architectural differences.

### Shared Capabilities

| Feature | tls-compliance-operator | openshift/tls-scanner |
|---------|------------------------|-----------------------|
| TLS version detection (1.0–1.3) | Yes | Yes |
| Cipher suite reporting | Yes | Yes |
| Certificate details | Yes | Yes |
| Non-compliant endpoint flagging | Yes | Yes |
| Namespace filtering (exclude) | Yes | Yes |

### Operator-Only Features

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
| Finer-grained failure statuses | Timeout, Closed, and Filtered states for unreachable endpoints |
| Include-mode namespace filtering | `--include-namespaces` for allow-list namespace monitoring |
| IANA/OpenSSL cipher name mapping | Bidirectional cipher suite name translation |
| Cipher strength grading (A-F) | Per-cipher and overall strength grades |
| OpenShift TLSSecurityProfile compliance | Checks against APIServer, IngressController, and KubeletConfig profiles |
| Arbitrary target scanning | `TLSComplianceTarget` CRD for scanning any host:port |
| Configurable worker pool | `--workers` flag for concurrent periodic scan throughput |
| CSV and JUnit XML export | `kubectl-tlsreport` plugin for CI/CD integration |
| Post-quantum readiness detection | Reports negotiated key exchange curves and PQC status |
| Pod IP and hostNetwork scanning | Discovers TLS servers on pod IPs even without a Service/Ingress/Route |

### Architectural Differences

| Aspect | tls-compliance-operator | openshift/tls-scanner |
|--------|------------------------|-----------------------|
| Execution model | Long-running controller with periodic rescans | Batch Job (run once, collect results) |
| TLS probing | Go `crypto/tls` | nmap with TLS scripts |
| Output format | Kubernetes CRDs + events + Prometheus | Raw scan results / reports |
| Discovery | Service, Ingress, Route watches + Pod IP scanning | Pod-level endpoint scanning via lsof |
| Deployment | Operator (Deployment + CRDs) | Job or CronJob |

## OpenShift Support

On OpenShift clusters, the operator automatically detects the
`route.openshift.io/v1` API and begins monitoring Routes with TLS termination.
On vanilla Kubernetes, Route monitoring is gracefully skipped.

## Prerequisites

- Kubernetes v1.28+ or OpenShift 4.x
- kubectl or oc CLI
- Cluster-admin privileges (for CRD installation)

## Development

```bash
# Build and test
make build          # Build binary
make test           # Run unit tests
make lint           # Run linter
make lint-fix       # Auto-fix lint issues

# Code generation (after editing *_types.go)
make manifests generate

# E2E tests
make test-e2e       # Creates Kind cluster, runs tests, cleans up

# Multi-arch build
make docker-buildx IMG=quay.io/bapalm/tls-compliance-operator:latest
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
