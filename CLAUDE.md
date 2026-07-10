# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubernetes operator (Kubebuilder) that monitors all TLS endpoints (Services, Ingresses, OpenShift Routes, and Pods) in a cluster for TLS version compliance. Checks which TLS versions (1.0, 1.1, 1.2, 1.3) each endpoint supports, flags non-compliant endpoints, reports certificate details, and provides observability via CRD status, Kubernetes events, and Prometheus metrics.

## Common Commands

```bash
# Build and test
make build                    # Build binary to bin/manager
make build-plugin             # Build kubectl-tlsreport plugin to bin/kubectl-tlsreport
make test                     # Unit tests with envtest (real K8s API + etcd)
make benchmark                # Run Go benchmark tests (tlscheck, endpoint)
make check-coverage           # Verify test coverage meets threshold (default 40%)
make lint                     # Run golangci-lint
make lint-fix                 # Auto-fix lint issues

# Run locally (uses current kubeconfig)
make run

# E2E tests
make setup-test-e2e           # Create Kind cluster for e2e tests
make test-e2e                 # Creates Kind cluster, runs tests, cleans up
make cleanup-test-e2e         # Tear down Kind cluster used for e2e tests

# Parity tests (compare operator results with tls-scanner)
make test-parity              # Run TLS parity tests

# Test server (configurable TLS server for testing)
make docker-build-testserver  # Build the TLS test server image
make docker-push-testserver   # Push the TLS test server image

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
- `cmd/kubectl-tlsreport/` - kubectl plugin for exporting and querying TLS compliance reports (see below)
- `api/v1alpha1/` - CRD schema (`TLSComplianceReport`, `TLSComplianceTarget`), edit `*_types.go` here
- `internal/controller/endpoint_controller.go` - Watches Services/Ingresses/Routes, scans Pods, creates TLSComplianceReport CRs
- `pkg/tlscheck/` - TLS endpoint checker using Go crypto/tls (interface-based, rate-limited)
- `pkg/endpoint/` - Endpoint extraction from K8s resources (Service, Ingress, Route, Pod)
- `pkg/export/` - Report export framework (CSV, JSON, JUnit XML, Markdown) with filtering and sorting
- `pkg/tlsprofile/` - OpenShift TLS security profile fetcher and compliance checker
- `internal/metrics/` - Prometheus metrics

**kubectl-tlsreport Plugin:**
- Standalone CLI built with Cobra, installed as `kubectl tlsreport`
- Subcommands: `summary` (compliance overview), `get` (table/wide/json listing), `describe` (detailed single report), `version`
- Root command exports reports in CSV, JSON, JUnit, or Markdown format
- Filtering flags: `--namespace`, `--status`, `--source`, `--pqc-status`, `--expires-within`, `--expired`, `--cert-issuer`, `--cert-subject`, `--selector`
- Sorting: `--sort-by` (host, port, compliance, expiry, grade, pqc)
- Build: `make build-plugin` (outputs `bin/kubectl-tlsreport`)

**Export Framework (`pkg/export/`):**
- `filter.go` - FilterOptions struct and FilterReports() with AND-combined criteria
- `sort.go` - SortReports() with stable sort by host/port/compliance/expiry/grade/pqc
- `summary.go` - ComputeSummary() aggregates stats (compliance rate, PQC readiness, cert expiry buckets)
- `csv.go`, `json.go`, `junit.go`, `markdown.go` - Format-specific writers

**TLS Profile Checking (`pkg/tlsprofile/`):**
- `profile.go` - Profile types (Old/Intermediate/Modern/Custom), predefined cipher suites, CheckCompliance()
- `fetcher.go` - Fetches TLS security profiles from OpenShift APIServer, IngressController, KubeletConfig; caches results with periodic refresh

**Test Infrastructure:**
- `test/e2e/` - E2E tests using Kind cluster (build tag `e2e`)
- `test/parity/` - Parity tests comparing operator results with openshift/tls-scanner output (build tag `parity`)
- `test/testserver/` - Configurable TLS test server (env-driven: TLS versions, mTLS, cert expiry, CN)
- `test/utils/` - Shared test utilities (command runner, project dir resolution)

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
- **Warning** = Partially compliant (e.g. supports modern TLS but also legacy versions)
- **Unreachable** = Could not connect (connection refused)
- **Timeout** = Connection timed out
- **Closed** = Port is closed
- **Filtered** = Port is filtered (firewall)
- **NoTLS** = Port is open but does not speak TLS
- **MutualTLSRequired** = Server requires a client certificate
- **Pending** = Scan not yet completed
- **Unknown** = Status could not be determined

**Config Structure:**
- `config/crd/` - Generated CRDs (DO NOT EDIT)
- `config/rbac/` - Generated RBAC (DO NOT EDIT manually, use kubebuilder markers)
- `config/manager/` - Deployment config
- `config/samples/` - Example CRs (safe to edit)
- `config/prometheus/` - ServiceMonitor for metrics scraping

## Requirements

- Go 1.26+

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
- **Export tests:** Comprehensive tests for CSV/JSON/JUnit/Markdown output, filtering, sorting, and summary stats
- **E2E tests:** Kind cluster, build tag `//go:build e2e`, located in `test/e2e/`
- **Parity tests:** Compare operator results with openshift/tls-scanner, build tag `//go:build parity`, located in `test/parity/`
- **Test server:** Configurable TLS server in `test/testserver/` for e2e/parity testing (supports env-driven TLS version, mTLS, cert expiry)

Run single test:
```bash
go test -v ./internal/controller/... -run TestSpecificName
go test -v ./pkg/tlscheck/... -run TestSpecificName
go test -v ./pkg/export/... -run TestSpecificName
```

## Key Files

| File | Purpose |
|------|---------|
| `api/v1alpha1/tlscompliancereport_types.go` | CRD schema definition |
| `internal/controller/endpoint_controller.go` | Main reconciliation logic |
| `pkg/tlscheck/checker.go` | TLS endpoint checking (interface + implementation) |
| `pkg/tlscheck/types.go` | TLS check result types |
| `pkg/endpoint/resolver.go` | Endpoint extraction from K8s resources |
| `pkg/export/filter.go` | Report filtering (namespace, status, source, PQC, cert expiry) |
| `pkg/export/summary.go` | Compliance summary statistics and output |
| `pkg/export/csv.go` | CSV export writer |
| `pkg/export/json.go` | JSON export writer |
| `pkg/export/junit.go` | JUnit XML export writer |
| `pkg/export/markdown.go` | Markdown export writer |
| `pkg/export/sort.go` | Report sorting by various fields |
| `pkg/tlsprofile/profile.go` | TLS profile types, predefined profiles, compliance checking |
| `pkg/tlsprofile/fetcher.go` | OpenShift TLS profile fetcher with caching |
| `cmd/kubectl-tlsreport/main.go` | kubectl plugin entry point (summary, get, describe, export) |
| `internal/metrics/metrics.go` | Prometheus metrics definitions |
| `test/testserver/main.go` | Configurable TLS test server for e2e/parity tests |
