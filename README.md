# TLS Compliance Operator

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

Continuously monitor all TLS endpoints in your Kubernetes or OpenShift cluster
for TLS version compliance, certificate health, and security posture.

## Overview

The TLS Compliance Operator is a Kubernetes operator that watches Services,
Ingresses, and OpenShift Routes to discover TLS endpoints, then probes each
endpoint to determine which TLS versions it supports. It creates
`TLSComplianceReport` custom resources with compliance status, supported TLS
versions, cipher suites, and certificate details.

**Use cases:**
- Enforce TLS 1.3 adoption across your cluster
- Detect endpoints still accepting TLS 1.0/1.1
- Monitor certificate expiration across all services
- Audit TLS configuration for compliance requirements

## Key Features

- **Automatic Discovery**: Watches Services (ports 443, 8443, https-*), Ingresses with TLS, and OpenShift Routes
- **TLS Version Detection**: Probes each endpoint for TLS 1.0, 1.1, 1.2, and 1.3 support
- **Compliance Classification**: Categorizes endpoints as Compliant, NonCompliant, Warning, or Error
- **Certificate Tracking**: Reports issuer, subject, DNS names, expiration, and days until expiry
- **Cipher Suite Reporting**: Records negotiated cipher suites per TLS version
- **OpenShift Support**: Automatically detects and monitors OpenShift Routes when available
- **Prometheus Metrics**: Exposes compliance status, certificate expiry, and TLS version support
- **Kubernetes Events**: Emits events for non-compliance, status changes, and certificate warnings
- **Rate Limiting**: Configurable rate limiting for TLS endpoint checks

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|    Services       |     |    Ingresses      |     |  OpenShift Routes |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                          |
         +------------+------------+-----------+--------------+
                      |                        |
              +-------v--------+    +----------v-----------+
              | Endpoint       |    | Route API Detection  |
              | Resolver       |    | (runtime)            |
              +-------+--------+    +----------+-----------+
                      |                        |
              +-------v------------------------v-------+
              |         Endpoint Controller            |
              |  - Creates TLSComplianceReport CRs     |
              |  - Triggers async TLS checks           |
              |  - Emits Kubernetes events              |
              +-------+--------------------------------+
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
1. **Controller** watches Services, Ingresses, and Routes for changes
2. **Endpoint Resolver** extracts TLS endpoints (host:port) from each resource
3. **TLS Checker** probes each endpoint with all TLS versions using Go's `crypto/tls`
4. **TLSComplianceReport** CR is created/updated with results
5. **Events and Metrics** are emitted for observability

## Compliance Logic

| Status | Condition |
|--------|-----------|
| **Compliant** | TLS 1.3 supported AND no TLS 1.0/1.1 |
| **NonCompliant** | TLS 1.0 or TLS 1.1 supported |
| **Warning** | TLS 1.3 not supported but no legacy TLS |
| **Error** | Could not connect to endpoint |
| **Pending** | Not yet checked |

## Quick Start

### Deploy from Source

```bash
# Build and push to your registry
make docker-build docker-push IMG=quay.io/youruser/tls-compliance-operator:latest

# Install CRDs and deploy
make install
make deploy IMG=quay.io/youruser/tls-compliance-operator:latest
```

### Or Generate Install Manifest

```bash
make build-installer IMG=quay.io/youruser/tls-compliance-operator:latest
kubectl apply -f dist/install.yaml
```

## Usage

Once deployed, the operator automatically discovers TLS endpoints and creates
`TLSComplianceReport` resources.

### View All TLS Compliance Reports

```bash
kubectl get tlscr

# Example output:
# NAME                                    HOST                                    PORT   SOURCE    COMPLIANCE     TLS1.3   TLS1.2   TLS1.0   CERT-EXPIRY   AGE
# my-service-443-a1b2c3d4                 my-service.default.svc.cluster.local    443    Service   Compliant      true     true     false    29d           5m
# api-ingress-443-e5f6g7h8                api.example.com                         443    Ingress   NonCompliant   true     true     true     180d          5m
# legacy-app-8443-i9j0k1l2                legacy.default.svc.cluster.local        8443   Service   Warning        false    true     false    7d            5m
```

### View Detailed Report

```bash
kubectl describe tlscr my-service-443-a1b2c3d4
```

### Find Non-Compliant Endpoints

```bash
kubectl get tlscr -o json | jq '.items[] | select(.status.complianceStatus == "NonCompliant") | .metadata.name'
```

### Find Endpoints with Expiring Certificates

```bash
kubectl get tlscr -o json | jq '.items[] | select(.status.certificateInfo.daysUntilExpiry < 30) | {name: .metadata.name, host: .spec.host, days: .status.certificateInfo.daysUntilExpiry}'
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
| `--exclude-namespaces` | `""` | Comma-separated namespaces to skip |
| `--cert-expiry-warning-days` | `30` | Days before expiry to emit warnings |
| `--metrics-bind-address` | `0` | Metrics endpoint bind address |
| `--health-probe-bind-address` | `:8081` | Health probe bind address |
| `--leader-elect` | `false` | Enable leader election for HA |

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
make docker-buildx IMG=quay.io/youruser/tls-compliance-operator:latest
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
