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

Filter by namespace, compliance status, or source kind:

```bash
# Only reports from a specific namespace
kubectl tlsreport csv -n openshift-monitoring

# Only non-compliant endpoints
kubectl tlsreport csv --status NonCompliant

# Only Route-sourced endpoints
kubectl tlsreport csv --source Route
```

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
