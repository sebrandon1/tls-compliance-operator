# Contributing

Contributions are welcome! This guide covers the development workflow.

## Prerequisites

- Go 1.26+
- Docker (for building images)
- kubectl / oc CLI
- A Kubernetes or OpenShift cluster (for testing)

## Development Setup

```bash
git clone https://github.com/sebrandon1/tls-compliance-operator.git
cd tls-compliance-operator
make build
make test
```

## Making Changes

### Code changes

```bash
make fmt       # Format code
make vet       # Run go vet
make lint      # Run golangci-lint
make test      # Run unit tests
```

### CRD or RBAC changes

If you edit `api/v1alpha1/*_types.go` or kubebuilder markers:

```bash
make manifests generate  # Regenerate CRDs, RBAC, and DeepCopy methods
```

Never edit files under `config/crd/bases/` or `config/rbac/role.yaml` directly
— they are generated from markers.

### Running locally

```bash
make run  # Uses your current kubeconfig
```

### E2E tests

```bash
make test-e2e  # Creates a Kind cluster, runs tests, cleans up
```

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes with tests
3. Run `make lint` and `make test` locally
4. Open a pull request against `main`
5. CI will run tests, linting, and security scans automatically

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- golangci-lint enforces style checks — run `make lint` before submitting
- Prefer table-driven tests
- Keep comments minimal — explain "why", not "what"
- `make check-coverage` requires at least 70% coverage (override with `COVERAGE_THRESHOLD`)

## Reporting Issues

Use [GitHub Issues](https://github.com/sebrandon1/tls-compliance-operator/issues)
to report bugs or request features. Include:

- Kubernetes/OpenShift version
- Operator version or commit
- Steps to reproduce
- Expected vs actual behavior
