# Exporting Reports

The `kubectl-tlsreport` plugin exports TLS compliance data in CSV, JSON, YAML,
JUnit XML, and Markdown formats for CI/CD pipelines, auditing, and dashboards.

## Install the Plugin

### Download a pre-built binary

Release binaries are published for `linux-amd64`, `linux-arm64`,
`darwin-amd64`, and `darwin-arm64`:

```bash
# Linux (amd64)
curl -LO https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/kubectl-tlsreport-linux-amd64
chmod +x kubectl-tlsreport-linux-amd64
sudo mv kubectl-tlsreport-linux-amd64 /usr/local/bin/kubectl-tlsreport

# macOS (Apple Silicon)
curl -LO https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/kubectl-tlsreport-darwin-arm64
chmod +x kubectl-tlsreport-darwin-arm64
sudo mv kubectl-tlsreport-darwin-arm64 /usr/local/bin/kubectl-tlsreport
```

### Build from source

```bash
make build-plugin
sudo mv bin/kubectl-tlsreport /usr/local/bin/
```

Once on your `PATH`, kubectl discovers it automatically as `kubectl tlsreport`.

## Export Formats

**CSV** (default):

```bash
kubectl tlsreport csv
```

**JSON**:

```bash
kubectl tlsreport json
```

**YAML**:

```bash
kubectl tlsreport yaml
```

**JUnit XML** (for CI test result ingestion):

```bash
kubectl tlsreport junit
```

**Markdown** (for GitHub issues, wikis, and documentation):

```bash
kubectl tlsreport markdown
kubectl tlsreport md  # shorthand
```

Produces a Markdown table matching `kubectl tlsreport get` columns:

```
| Host | Port | Source | Compliance | Grade | FS | TLS1.3 | TLS1.2 | TLS1.0 | PQC | MLKEM | CertExpiry | Age |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-service.default | 443 | Service | Compliant | A | true | true | true | false | PQCReady | true | 364 | 5m |
```

## Querying Reports

### List reports (`get`)

The `get` subcommand lists reports in table format with output options:

```bash
# Default table output
kubectl tlsreport get

# Wide output (adds namespace, TLS 1.0, SSL 3.0, issuer, cert expiry)
kubectl tlsreport get -o wide

# JSON output
kubectl tlsreport get -o json

# YAML output
kubectl tlsreport get -o yaml
```

### Detailed report (`describe`)

The `describe` subcommand shows the full report for a single endpoint:

```bash
kubectl tlsreport describe google-com-443-01d44386
```

### Summary (`summary`)

Get an at-a-glance compliance summary:

```bash
kubectl tlsreport summary
```

### Version

```bash
kubectl tlsreport version
```

## Filtering

Filter by namespace, compliance status, source kind, PQC readiness, TLS version,
cipher grade, or certificate expiry:

```bash
# Only reports from a specific namespace
kubectl tlsreport csv -n openshift-monitoring

# Only non-compliant endpoints
kubectl tlsreport csv --status NonCompliant

# Only Route-sourced endpoints
kubectl tlsreport csv --source Route

# Only endpoints not yet PQC-ready
kubectl tlsreport csv --pqc-status LegacyTLS

# Endpoints that support TLS 1.2
kubectl tlsreport csv --tls-version 1.2

# Exact cipher grade
kubectl tlsreport csv --grade A

# Minimum cipher grade (A and B)
kubectl tlsreport csv --min-grade B

# Certificates expiring within 30 days
kubectl tlsreport csv --expires-within 30d

# Only expired certificates
kubectl tlsreport csv --expired

# Combine filters: non-PQC-ready services in production
kubectl tlsreport json --source Service -n production --pqc-status TLS13Capable
```

All filters use AND logic. PQC status values: `PQCReady`, `TLS13Capable`, `LegacyTLS`, `NoPQC`.
The `--expires-within` flag accepts day-based durations (e.g. `7d`, `30d`, `90d`) or Go durations (e.g. `24h`).
The `--expired` flag excludes endpoints without certificates.

### Label selectors

Filter reports by Kubernetes label using `--selector` / `-l`:

```bash
# Only hostNetwork pod endpoints
kubectl tlsreport csv -l tls-compliance.telco.openshift.io/host-network=true

# Custom labels
kubectl tlsreport json -l env=production
```

### Certificate filters

```bash
# Filter by certificate issuer (substring match)
kubectl tlsreport csv --cert-issuer "Let's Encrypt"

# Filter by certificate subject (substring match)
kubectl tlsreport csv --cert-subject "*.example.com"
```

## Sorting

Sort results with `--sort-by`:

```bash
# Sort by hostname
kubectl tlsreport csv --sort-by host

# Sort by certificate expiry (soonest first)
kubectl tlsreport csv --sort-by expiry

# Sort by cipher grade
kubectl tlsreport csv --sort-by grade

# Sort by PQC readiness
kubectl tlsreport csv --sort-by pqc

# Combine with filters: non-compliant endpoints sorted by expiry
kubectl tlsreport csv --status NonCompliant --sort-by expiry
```

Supported sort keys: `host`, `port`, `compliance`, `expiry`, `grade`, `pqc`.
Endpoints without certificates sort to the end when sorting by `expiry`.

## CI/CD Integration

### Pipeline gating with --fail-on-non-compliant

Use `--fail-on-non-compliant` to exit with code 1 when any non-compliant
endpoints are found (NonCompliant, NoTLS, or PlaintextHTTP). Infrastructure
statuses like Timeout and Unreachable do not trigger a failure.

```bash
# Gate on all endpoints
kubectl tlsreport summary --fail-on-non-compliant

# Export JUnit and gate in one step
kubectl tlsreport junit --fail-on-non-compliant > tls-results.xml

# Gate on a specific namespace
kubectl tlsreport get -n production --fail-on-non-compliant

# Gate on a specific source kind
kubectl tlsreport summary --source Service --fail-on-non-compliant

# Combine: non-compliant services in production
kubectl tlsreport json -n production --source Service --fail-on-non-compliant
```

The flag works with all subcommands and respects all filter flags.

### JUnit XML for test result ingestion

```bash
kubectl tlsreport junit > tls-results.xml
```

Most CI systems (Jenkins, GitLab CI, GitHub Actions) can ingest JUnit XML and
display test results natively.

See [CI/CD Integration](ci-integration.md) for full pipeline examples
(GitHub Actions, Jenkins, Prow, Tekton, run-once scan mode).

---

Next: [Troubleshooting](troubleshooting.md)
