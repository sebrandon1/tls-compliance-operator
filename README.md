# TLS Compliance Operator

> **See also:** [openshift/tls-scanner](https://github.com/openshift/tls-scanner) — a batch Job-based TLS auditing tool from the OpenShift team. If you want a one-shot scan or are looking for alternatives, check it out.
>
> **See also:** [tls-config-lint](https://github.com/sebrandon1/tls-config-lint) — a GitHub Action that scans source code for TLS configuration anti-patterns (shift-left). Use **tls-config-lint** to catch issues during development and **tls-compliance-operator** to verify runtime compliance in your cluster.

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

Continuously monitor all TLS endpoints in your Kubernetes or OpenShift cluster
for TLS version compliance, certificate health, and security posture.

## Overview

The TLS Compliance Operator watches Services, Ingresses, OpenShift Routes,
Gateway API resources (HTTPRoute, TLSRoute, Gateway), and Pods to discover TLS
endpoints, then probes each endpoint to determine which TLS versions it
supports. It creates `TLSComplianceReport` custom resources with compliance
status, supported TLS versions, cipher suites, certificate details, and
post-quantum readiness.

## Key Features

- **Automatic Discovery** — Services, Ingresses, Routes, Pods, and ExternalName services
- **Gateway API Support** — Auto-discovers HTTPRoute, TLSRoute, and Gateway resources
- **Headless Service Scanning** — Discovers pod endpoints via EndpointSlice API
- **TLS Version Detection** — Probes for SSL 3.0, TLS 1.0, 1.1, 1.2, and 1.3 support (in parallel)
- **Compliance Classification** — Compliant, NonCompliant, Timeout, Closed, NoTLS, MutualTLSRequired
- **Certificate Tracking** — Issuer, subject, DNS names, expiration, chain length, public key details
- **Cipher Strength Grading** — A-F grades for negotiated cipher suites
- **Forward Secrecy Detection** — Identifies whether all cipher suites use ephemeral key exchange (ECDHE/DHE)
- **ALPN Protocol Detection** — Reports negotiated application-layer protocols (h2, http/1.1)
- **Post-Quantum Readiness** — Detects post-quantum key exchange (X25519MLKEM768) via passive and [active ML-KEM probing](docs/pqc-mlkem.md)
- **Prometheus Metrics** — Compliance status, certificate expiry, TLS versions, PQC readiness, forward secrecy
- **Kubernetes Events** — Non-compliance, status changes, certificate warnings, PQC readiness changes
- **OpenShift TLS Profiles** — Checks against APIServer, IngressController, and KubeletConfig profiles
- **Arbitrary Targets** — Scan any host:port via `TLSComplianceTarget` CRD with webhook validation
- **mTLS Client Certificates** — Optionally provide client certs for probing mTLS-protected endpoints
- **Per-Namespace Rate Limiting** — Fine-grained rate control for sensitive namespaces
- **Report Export** — CSV, JSON, YAML, JUnit XML, and Markdown via `kubectl-tlsreport` plugin

## Quick Deploy

```bash
kubectl apply -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

To uninstall:

```bash
kubectl delete -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

## Guides

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Deploy to your cluster in one command |
| [Configuration](docs/configuration.md) | Flags, environment variables, resource sizing |
| [Architecture](docs/architecture.md) | How the operator works, compliance logic |
| [Viewing Reports](docs/viewing-reports.md) | Compliance status, cipher grades, certificate info |
| [Post-Quantum / ML-KEM](docs/pqc-mlkem.md) | PQC readiness detection, active ML-KEM probing |
| [Prometheus Metrics](docs/metrics.md) | Metrics reference and example PromQL queries |
| [Custom Targets](docs/custom-targets.md) | Scan arbitrary external hosts with TLSComplianceTarget |
| [Exporting Reports](docs/exporting-reports.md) | CSV, JSON, YAML, JUnit, Markdown export with filtering |
| [Comparison](docs/comparison.md) | Feature comparison with openshift/tls-scanner |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and fixes |

## Prerequisites

- Kubernetes v1.28+ or OpenShift 4.x
- kubectl or oc CLI
- Cluster-admin privileges (for CRD installation)
- Go 1.26+ (for development)

## Development

```bash
make build          # Build binary
make test           # Run unit tests
make lint           # Run linter
make manifests generate  # After editing *_types.go
make test-e2e       # E2E tests (creates Kind cluster)
make docker-buildx IMG=quay.io/bapalm/tls-compliance-operator:latest  # Multi-arch build
```

## Blog Posts

- [See What Your Cluster Is Really Serving: TLS Visibility with the tls-compliance-operator](https://blog.palmsoftware.org/2026/05/06/see-what-your-cluster-is-really-serving-tls-visibility-with-the-tls-compliance-operator/)

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
