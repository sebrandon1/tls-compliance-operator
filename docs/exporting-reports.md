# Exporting Reports

The `kubectl-tlsreport` plugin exports TLS compliance data in CSV, JSON, and
JUnit XML formats for CI/CD pipelines, auditing, and dashboards.

## Install the Plugin

Build from source:

```bash
go build -o kubectl-tlsreport ./cmd/kubectl-tlsreport/
sudo mv kubectl-tlsreport /usr/local/bin/
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

**JUnit XML** (for CI test result ingestion):

```bash
kubectl tlsreport junit
```

## Filtering

Filter by namespace, compliance status, source kind, PQC readiness, or certificate expiry:

```bash
# Only reports from a specific namespace
kubectl tlsreport csv -n openshift-monitoring

# Only non-compliant endpoints
kubectl tlsreport csv --status NonCompliant

# Only Route-sourced endpoints
kubectl tlsreport csv --source Route

# Only endpoints not yet PQC-ready
kubectl tlsreport csv --pqc-status LegacyTLS

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

## Summary View

Get an at-a-glance compliance summary:

```bash
kubectl tlsreport summary
```

## CI/CD Integration

Use JUnit export to fail a pipeline when non-compliant endpoints exist:

```bash
kubectl tlsreport junit > tls-results.xml
```

Most CI systems (Jenkins, GitLab CI, GitHub Actions) can ingest JUnit XML and
display test results natively.

---

Next: [Troubleshooting](troubleshooting.md)
