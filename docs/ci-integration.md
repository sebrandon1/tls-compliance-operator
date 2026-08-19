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
| `--scan-all-ports` | `TLS_COMPLIANCE_SCAN_ALL_PORTS` | Scan all declared TCP container ports on pods, not just known TLS ports |

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

### Example: Quick Start

Scan any cluster you have `KUBECONFIG` access to in three steps:

```bash
git clone https://github.com/sebrandon1/tls-compliance-operator.git
cd tls-compliance-operator
make deploy-run-once-scan
```

This is the recommended approach for most users. It installs the CRDs,
creates a namespace with RBAC, deploys the operator as a one-shot
Kubernetes Job, waits for completion, copies the results locally, and
tears down all resources on exit. The exit code tells you the result:
0 = compliant, 1 = non-compliant, 2 = error.

The underlying script is at
[`hack/deploy-run-once-scan.sh`](../hack/deploy-run-once-scan.sh) if you
need to adapt it for your own pipeline.

If you prefer to build and run the binary locally instead of deploying a
Job, use `make run-once`.

Customize either target with the same Make variables:

```bash
# Scan only specific namespaces
make run-once SCAN_NAMESPACES=my-app,my-other-app

# JSON output to a custom path
make deploy-run-once-scan SCAN_FORMAT=json SCAN_FILE=report.json

# Deploy-scan with a specific image and namespace filter
make deploy-run-once-scan IMG=quay.io/bapalm/tls-compliance-operator:v1.1.4 \
  SCAN_NAMESPACES=my-app SCAN_FORMAT=json SCAN_FILE=report.json
```

| Variable | Default | Options |
|----------|---------|---------|
| `SCAN_FORMAT` | `junit` | `csv`, `json`, `yaml`, `junit`, `markdown` |
| `SCAN_FILE` | `results.xml` | Any file path |
| `SCAN_NAMESPACES` | *(all)* | Comma-separated namespace list |
| `IMG` | `quay.io/bapalm/tls-compliance-operator:latest` | Any container image (`deploy-run-once-scan` only) |
| `SCAN_NAMESPACE` | `tls-compliance-scan` | Namespace for the scan Job (`deploy-run-once-scan` only) |

Infrastructure statuses like Timeout and Unreachable do not trigger exit
code 1, preventing transient network issues from failing your CI pipeline.

#### Sample JSON Output

Running with `SCAN_FORMAT=json` produces an array of report objects:

```json
[
  {
    "crName": "console-openshift-console-443-a1b2c3d4",
    "host": "console.openshift-console.svc",
    "port": "443",
    "source": "Service",
    "namespace": "openshift-console",
    "name": "console",
    "compliance": "Compliant",
    "grade": "A",
    "forwardSecrecy": true,
    "keyExchangeTypes": {
      "TLS 1.2": "ECDHE",
      "TLS 1.3": "X25519MLKEM768"
    },
    "tls13": true,
    "tls12": true,
    "tls11": false,
    "tls10": false,
    "ssl30": false,
    "quantumReady": true,
    "pqcReadiness": "PQCReady",
    "mlkemSupported": true,
    "certExpiry": "2027-01-15",
    "certIssuer": "kube-apiserver-service-network-signer",
    "publicKeyAlgorithm": "ECDSA",
    "publicKeyBits": 256,
    "signatureAlgorithm": "ECDSAWithSHA256",
    "chainLength": 2,
    "alpnProtocols": {
      "TLS 1.2": "h2",
      "TLS 1.3": "h2"
    },
    "scanDuration": "1.234s"
  },
  {
    "crName": "downloads-openshift-console-8080-e5f6a7b8",
    "host": "downloads.openshift-console.svc",
    "port": "8080",
    "source": "Service",
    "namespace": "openshift-console",
    "name": "downloads",
    "compliance": "NoTLS",
    "grade": "",
    "forwardSecrecy": false,
    "tls13": false,
    "tls12": false,
    "tls11": false,
    "tls10": false,
    "ssl30": false,
    "quantumReady": false,
    "pqcReadiness": "NoPQC",
    "mlkemSupported": false,
    "certExpiry": "",
    "certIssuer": "",
    "scanDuration": "0.052s"
  }
]
```

Key fields for ML-KEM/PQC validation:
- **`crName`** — TLSComplianceReport resource name
- **`pqcReadiness`** — `PQCReady`, `TLS13Capable`, `LegacyTLS`, or `NoPQC`
- **`mlkemSupported`** — `true` if active ML-KEM probing confirmed hybrid key exchange
- **`quantumReady`** — `true` if passive detection found a post-quantum curve
- **`keyExchangeTypes`** — per-TLS-version negotiated key exchange (e.g., `X25519MLKEM768`)

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

## Comparing snapshots after an upgrade

Save a JSON snapshot before a cluster upgrade or TLS profile change, then
diff it against the live cluster (or a second export) afterward.

`--fail-on-regression` exits with code 1 when an existing endpoint gets worse
(compliance, cipher grade, newly enabled legacy TLS, lost TLS 1.3, or worse
PQC readiness) or when a newly added endpoint is non-compliant.

```bash
kubectl tlsreport json > before.json
# ... upgrade ...
kubectl tlsreport json > after.json
kubectl tlsreport diff before.json after.json --fail-on-regression
```

### Example: GitHub Actions (upgrade validation)

```yaml
- name: Capture TLS baseline
  run: kubectl tlsreport json > before.json

# ... upgrade steps ...

- name: Diff TLS posture
  run: kubectl tlsreport diff before.json --fail-on-regression
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
