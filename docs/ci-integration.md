# CI/CD Integration

The tls-compliance-operator supports two modes for CI/CD pipeline integration:

1. **Run-once scan mode** — deploy the operator, scan all endpoints once, and exit
   with a pass/fail exit code
2. **kubectl tlsreport gating** — query existing scan results and fail the pipeline
   if non-compliant endpoints are found

## Exit Codes

Both modes use the same exit code semantics:

| Code | Meaning |
|------|---------|
| 0 | All endpoints are TLS-compliant |
| 1 | Non-compliant endpoints detected (NonCompliant, NoTLS, or PlaintextHTTP) |
| 2 | Scan or runtime error (run-once mode only) |

Infrastructure statuses like Timeout and Unreachable do not trigger exit code 1.
This prevents transient network issues from failing your CI pipeline.

## Run-Once Scan Mode

The `--run-once` flag tells the operator to perform a single full scan and exit
immediately. This is the recommended approach for ephemeral test environments
where you want to deploy, scan, and tear down.

```bash
bin/manager --run-once \
  --output-format junit \
  --output-file results.xml
```

### Flags

| Flag | Env Var | Description |
|------|---------|-------------|
| `--run-once` | `TLS_COMPLIANCE_RUN_ONCE` | Perform a single scan and exit |
| `--output-format` | `TLS_COMPLIANCE_OUTPUT_FORMAT` | Output format: `csv`, `json`, `yaml`, `junit`, `markdown` |
| `--output-file` | `TLS_COMPLIANCE_OUTPUT_FILE` | Path to write results (defaults to stdout) |

In run-once mode, leader election, health probes, and metrics serving are
automatically disabled since they are not needed for a one-shot scan.

### Example: Generic CI Script

```bash
#!/bin/bash
set -e

# Deploy operator and CRDs
make deploy IMG=quay.io/bapalm/tls-compliance-operator:latest

# Wait for controller to be ready
kubectl rollout status deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system --timeout=120s

# Run a one-shot scan (the operator's periodic scan runs on startup)
# Wait for scan to complete, then export results
sleep 60
kubectl tlsreport junit > results.xml

# Check compliance
kubectl tlsreport summary --fail-on-non-compliant
```

### Example: Run-Once in a Container

For environments where the operator runs as a Job rather than a Deployment:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: tls-compliance-scan
spec:
  template:
    spec:
      serviceAccountName: tls-compliance-operator-controller-manager
      containers:
        - name: scanner
          image: quay.io/bapalm/tls-compliance-operator:latest
          args:
            - --run-once
            - --output-format=junit
            - --output-file=/results/report.xml
            - --workers=10
          volumeMounts:
            - name: results
              mountPath: /results
      volumes:
        - name: results
          emptyDir: {}
      restartPolicy: Never
  backoffLimit: 0
```

The Job exits with code 0 if all endpoints are compliant, 1 if any are
non-compliant, or 2 if the scan itself fails. CI systems can use the Job's
exit code directly to gate the pipeline.

## kubectl tlsreport Gating

If the operator is already running in the cluster (e.g., installed as part of
your platform), use `kubectl tlsreport` with `--fail-on-non-compliant` to
query results without deploying anything new.

```bash
kubectl tlsreport summary --fail-on-non-compliant
echo "Exit code: $?"
```

This works with all report subcommands:

```bash
# Check all endpoints
kubectl tlsreport get --fail-on-non-compliant

# Check a specific namespace
kubectl tlsreport summary -n my-app --fail-on-non-compliant

# Export JUnit and fail on non-compliance
kubectl tlsreport junit --fail-on-non-compliant > results.xml

# Filter to a specific status for targeted checks
kubectl tlsreport get --status PlaintextHTTP --fail-on-non-compliant
```

### Example: Prow Test Step

```yaml
- name: tls-compliance-check
  image: quay.io/bapalm/tls-compliance-operator:latest
  command:
    - kubectl
    - tlsreport
    - summary
    - --fail-on-non-compliant
  env:
    - name: KUBECONFIG
      value: /etc/kubeconfig/config
```

### Example: Konflux Integration Task

```yaml
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: tls-compliance-gate
spec:
  steps:
    - name: check-compliance
      image: quay.io/bapalm/tls-compliance-operator:latest
      script: |
        #!/bin/bash
        kubectl tlsreport junit --fail-on-non-compliant > $(results.junit.path)
      results:
        - name: junit
          type: string
```

### Example: Jenkins Pipeline

```groovy
stage('TLS Compliance') {
    steps {
        sh '''
            kubectl tlsreport junit --fail-on-non-compliant > tls-results.xml
        '''
        junit 'tls-results.xml'
    }
}
```

### Example: GitHub Actions

```yaml
- name: Check TLS Compliance
  run: |
    kubectl tlsreport summary --fail-on-non-compliant

- name: Export JUnit Results
  if: always()
  run: |
    kubectl tlsreport junit > tls-results.xml

- name: Publish Test Results
  if: always()
  uses: dorny/test-reporter@v1
  with:
    name: TLS Compliance
    path: tls-results.xml
    reporter: java-junit
```

## Combining with Filters

The `--fail-on-non-compliant` flag respects all filter flags. This lets you
scope compliance checks to specific namespaces, sources, or statuses:

```bash
# Only check services in the production namespace
kubectl tlsreport summary -n production --source Service --fail-on-non-compliant

# Only fail on plaintext HTTP (ignore generic NoTLS)
kubectl tlsreport get --status PlaintextHTTP --fail-on-non-compliant

# Check endpoints with expiring certificates
kubectl tlsreport get --expires-within 30d --fail-on-non-compliant
```
