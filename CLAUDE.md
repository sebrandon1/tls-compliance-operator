# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubernetes operator (Kubebuilder) that monitors all TLS endpoints (Services, Ingresses, OpenShift Routes, and Pods) in a cluster for TLS version compliance. Checks which TLS versions (1.0, 1.1, 1.2, 1.3) each endpoint supports, flags non-compliant endpoints, reports certificate details, and provides observability via CRD status, Kubernetes events, and Prometheus metrics.

## Common Commands

```bash
# Build and test
make build                    # Build binary to bin/manager
make test                     # Unit tests with envtest (real K8s API + etcd)
make lint                     # Run golangci-lint
make lint-fix                 # Auto-fix lint issues

# Run locally (uses current kubeconfig)
make run

# E2E tests
make test-e2e                 # Creates Kind cluster, runs tests, cleans up

# Code generation (run after editing *_types.go or markers)
make manifests                # Regenerate CRDs/RBAC from kubebuilder markers
make generate                 # Regenerate DeepCopy methods

# Docker
make docker-build IMG=quay.io/bapalm/tls-compliance-operator:latest   # Build image
make docker-push IMG=quay.io/bapalm/tls-compliance-operator:latest    # Push image
make docker-buildx IMG=quay.io/bapalm/tls-compliance-operator:latest  # Multi-arch build (amd64, arm64, s390x, ppc64le)

# Deploy to cluster
make install                  # Install CRDs only
make deploy IMG=<img>         # Full deployment
make build-installer IMG=<img> # Generate dist/install.yaml
```

## Architecture

**Core Components:**
- `cmd/main.go` - Manager entry point, initializes TLS checker and controller
- `api/v1alpha1/` - CRD schema (`TLSComplianceReport`), edit `*_types.go` here
- `internal/controller/endpoint_controller.go` - Watches Services/Ingresses/Routes, scans Pods, creates TLSComplianceReport CRs
- `pkg/tlscheck/` - TLS endpoint checker using Go crypto/tls (interface-based, rate-limited)
- `pkg/endpoint/` - Endpoint extraction from K8s resources (Service, Ingress, Route, Pod)
- `internal/metrics/` - Prometheus metrics

**Key Patterns:**
- Single controller with three watches (Service, Ingress, Route) plus periodic Pod scanning to avoid CR conflicts
- TLS checker uses `crypto/tls` with `InsecureSkipVerify` (reports cert info but doesn't enforce trust)
- OpenShift Route API detected at startup via REST mapper; gracefully skipped on vanilla K8s
- Interface-based TLS checker (`tlscheck.Checker`) enables mock injection for tests
- Rate-limited checker wraps base checker with `golang.org/x/time/rate`
- Periodic scan loop (default 1h) re-checks all endpoints
- Cleanup loop (default 5m) removes CRs for deleted source resources
- CR naming: `<sanitized-host>-<port>-<8-char-hash>` for uniqueness

**Compliance Logic:**
- **Compliant** = Supports TLS 1.2 or 1.3 (older versions alongside are fine)
- **NonCompliant** = Only supports TLS 1.0/1.1, no modern TLS
- **Unreachable** = Could not connect (connection refused, timeout)
- **NoTLS** = Port is open but does not speak TLS
- **MutualTLSRequired** = Server requires a client certificate

**Config Structure:**
- `config/crd/` - Generated CRDs (DO NOT EDIT)
- `config/rbac/` - Generated RBAC (DO NOT EDIT manually, use kubebuilder markers)
- `config/manager/` - Deployment config
- `config/samples/` - Example CRs (safe to edit)
- `config/prometheus/` - ServiceMonitor for metrics scraping

## Development Rules

**Never edit (auto-generated):**
- `config/crd/bases/*.yaml`
- `config/rbac/role.yaml`
- `**/zz_generated.*.go`

**Never remove:**
- `// +kubebuilder:scaffold:*` comments (CLI injects code here)

**After changing API types or markers:**
```bash
make manifests generate
```

**After editing Go files:**
```bash
make fmt && make vet && make test
```

## Testing

- **Unit tests:** Standard Go testing with fake client (controller-runtime)
- **TLS checker tests:** Use `httptest` TLS servers with specific TLS versions
- **E2E tests:** Kind cluster, build tag `//go:build e2e`, located in `test/e2e/`

Run single test:
```bash
go test -v ./internal/controller/... -run TestSpecificName
go test -v ./pkg/tlscheck/... -run TestSpecificName
```

## Key Files

| File | Purpose |
|------|---------|
| `api/v1alpha1/tlscompliancereport_types.go` | CRD schema definition |
| `internal/controller/endpoint_controller.go` | Main reconciliation logic |
| `pkg/tlscheck/checker.go` | TLS endpoint checking (interface + implementation) |
| `pkg/tlscheck/types.go` | TLS check result types |
| `pkg/endpoint/resolver.go` | Endpoint extraction from K8s resources |
| `internal/metrics/metrics.go` | Prometheus metrics definitions |
