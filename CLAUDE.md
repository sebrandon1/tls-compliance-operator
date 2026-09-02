# CLAUDE.md

Guidance for working in this repository.

## Overview

Kubebuilder operator that discovers TLS endpoints (Services including
ExternalName/NodePort/LoadBalancer, Ingresses, OpenShift Routes, Gateway API
resources, Pods, and `TLSComplianceTarget` CRs) and probes TLS versions,
ciphers, certificates, and post-quantum (ML-KEM) readiness. Results are stored
as `TLSComplianceReport` CRs, Kubernetes events, and Prometheus metrics.

Compliance statuses, PQC levels, and scan flow are documented in
[docs/architecture.md](docs/architecture.md).

## Commands

```bash
# Build and test
make build                    # bin/manager
make build-plugin             # bin/kubectl-tlsreport
make package-plugin           # dist/kubectl-tlsreport-$GOOS-$GOARCH.tar.gz (Krew)
make test                     # unit tests (envtest) + Krew packaging checks
make benchmark                # Go benchmarks
make check-coverage           # default threshold 70%
make lint                     # golangci-lint
make lint-fix

# Run locally (current kubeconfig)
make run
make run-once                 # single scan, then exit

# E2E / parity
make setup-test-e2e
make test-e2e                 # Kind cluster, run, cleanup
make cleanup-test-e2e
make test-parity              # compare with openshift/tls-scanner

# Test server image
make docker-build-testserver
make docker-push-testserver

# After editing *_types.go or kubebuilder markers
make manifests generate

# Images and deploy
make docker-build IMG=quay.io/bapalm/tls-compliance-operator:latest
make docker-push IMG=quay.io/bapalm/tls-compliance-operator:latest
make docker-buildx IMG=quay.io/bapalm/tls-compliance-operator:latest
make install                  # CRDs only
make deploy IMG=<img>
make build-installer IMG=<img>  # dist/install.yaml
```

Requires **Go 1.26+**.

## Layout

| Path | Role |
|------|------|
| `cmd/main.go` | Manager: flags, TLS checker, controller setup |
| `cmd/kubectl-tlsreport/` | Cobra plugin (`kubectl tlsreport`) |
| `plugins/tlsreport.yaml` | Krew manifest (SHA-pinned copy also uploaded on each release) |
| `hack/package-plugin.sh` | Pack plugin binary + LICENSE into a Krew tar.gz |
| `api/v1alpha1/` | CRD types (`TLSComplianceReport`, `TLSComplianceTarget`) |
| `internal/controller/` | Watches, periodic scan, cleanup, circuit breaker |
| `pkg/tlscheck/` | TLS probing (`crypto/tls`, rate-limited) |
| `pkg/endpoint/` | Endpoint extraction from K8s resources |
| `pkg/export/` | Filter/sort/summary + CSV/JSON/YAML/JUnit/Markdown/HTML/SARIF export |
| `pkg/tlsprofile/` | OpenShift TLS security profiles |
| `internal/metrics/` | Prometheus metrics |
| `test/e2e/`, `test/parity/`, `test/testserver/` | Integration and fixture tests |

Single controller: watches Service, Ingress, Route (if present), Gateway API
kinds, and `TLSComplianceTarget`. Periodic Pod scans avoid CR ownership fights.
CR names are `<sanitized-host>-<port>-<8-char-hash>`. Scan interval defaults to
1h; cleanup to 5m. Endpoints that fail Timeout/Unreachable 3 times are skipped
for 15m (circuit breaker).

OpenShift Route and Gateway API kinds are detected via the REST mapper and
skipped on clusters that lack them.

## Rules

**Never edit:** `config/crd/bases/*.yaml`, `config/rbac/role.yaml`, `**/zz_generated.*.go`.

**Never remove:** `// +kubebuilder:scaffold:*` comments.

After API/marker changes: `make manifests generate`.

After Go edits: `make fmt && make vet && make test`.

Single-package tests:

```bash
go test -v ./internal/controller/... -run TestSpecificName
go test -v ./pkg/tlscheck/... -run TestSpecificName
go test -v ./pkg/export/... -run TestSpecificName
```
