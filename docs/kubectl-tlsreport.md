# kubectl-tlsreport Reference

The `kubectl-tlsreport` plugin provides CLI access to TLS compliance data
in your cluster. Once installed, kubectl discovers it as `kubectl tlsreport`.

## Install

### Download a pre-built binary

Pre-built binaries are available in `dist/plugins/` for multiple platforms:

```bash
# Linux (amd64)
sudo cp dist/plugins/kubectl-tlsreport-linux-amd64 /usr/local/bin/kubectl-tlsreport
sudo chmod +x /usr/local/bin/kubectl-tlsreport

# macOS (Apple Silicon)
sudo cp dist/plugins/kubectl-tlsreport-darwin-arm64 /usr/local/bin/kubectl-tlsreport
sudo chmod +x /usr/local/bin/kubectl-tlsreport
```

Available platforms: `linux-amd64`, `linux-arm64`, `linux-ppc64le`, `linux-s390x`,
`darwin-amd64`, `darwin-arm64`.

### Build from source

```bash
make build-plugin
sudo mv bin/kubectl-tlsreport /usr/local/bin/
```

## Global Flags

These flags are available on all subcommands:

| Flag | Short | Description |
|------|-------|-------------|
| `--namespace` | `-n` | Filter by source namespace |
| `--status` | | Filter by compliance status (Compliant, NonCompliant, Warning, Unreachable, Timeout, Closed, Filtered, NoTLS, PlaintextHTTP, MutualTLSRequired, Pending, Unknown) |
| `--source` | | Filter by source kind (Service, Ingress, Route, Pod, HTTPRoute, TLSRoute, Gateway, Target) |
| `--pqc-status` | | Filter by PQC readiness (PQCReady, TLS13Capable, LegacyTLS, NoPQC) |
| `--expires-within` | | Show certs expiring within duration (e.g. 30d, 7d, 90d) |
| `--expired` | | Show only expired certificates |
| `--cert-issuer` | | Filter by certificate issuer (substring match) |
| `--cert-subject` | | Filter by certificate subject (substring match) |
| `--tls-version` | | Filter by TLS version support (1.0, 1.1, 1.2, 1.3, ssl3.0) |
| `--grade` | | Filter by exact cipher grade (A, B, C, D, F) |
| `--min-grade` | | Filter by minimum cipher grade (e.g. B shows A and B) |
| `--sort-by` | | Sort results (host, port, compliance, expiry, grade, pqc) |
| `--selector` | `-l` | Label selector to filter reports |
| `--fail-on-non-compliant` | | Exit with code 1 if any non-compliant endpoints are found |
| `--kubeconfig` | | Path to kubeconfig file |
| `--context` | | Kubeconfig context to use |

## Subcommands

### Export (root command)

Export reports in CSV, JSON, YAML, JUnit XML, or Markdown format.

```bash
kubectl tlsreport [csv|json|yaml|junit|markdown|md]
```

CSV is the default format when no argument is given.

```bash
# Export as CSV
kubectl tlsreport csv

# Export as JSON
kubectl tlsreport json

# Export as JUnit XML for CI ingestion
kubectl tlsreport junit

# Export as Markdown
kubectl tlsreport markdown

# Export non-compliant endpoints as JSON
kubectl tlsreport json --status NonCompliant

# Export with CI gating (exit 1 on non-compliance)
kubectl tlsreport junit --fail-on-non-compliant > results.xml
```

### get

Display reports in a table. Supports `table`, `wide`, `json`, and `yaml`
output formats.

```bash
kubectl tlsreport get [name] [-o format]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `table` | Output format: table, wide, json, yaml |

```bash
# List all reports
kubectl tlsreport get

# Wide output (includes TLS 1.0, SSL 3.0, ML-KEM, issuer, cert expiry)
kubectl tlsreport get -o wide

# Get a specific report by name
kubectl tlsreport get my-service-443-abc12345

# Get non-compliant endpoints in a namespace
kubectl tlsreport get --status NonCompliant -n production

# Get reports as JSON
kubectl tlsreport get -o json
```

### describe

Show the full detail view for a single report, including TLS versions,
cipher suites, certificate info, key exchange, ALPN, and scan history.

```bash
kubectl tlsreport describe <name>
```

```bash
kubectl tlsreport describe google-com-443-01d44386
```

### summary

Show an at-a-glance compliance summary with counts by status, PQC readiness
breakdown, and certificate expiry buckets.

```bash
kubectl tlsreport summary
```

```bash
# Summary for all endpoints
kubectl tlsreport summary

# Summary for a specific namespace
kubectl tlsreport summary -n production

# Summary with CI gating
kubectl tlsreport summary --fail-on-non-compliant
```

### rescan

Trigger an immediate rescan of one or more reports by setting a rescan
annotation. The operator detects the annotation, performs a fresh TLS check,
and removes the annotation when complete.

```bash
kubectl tlsreport rescan [name] [--all] [--wait] [--timeout duration]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Rescan all reports matching current filters |
| `--wait` | `false` | Wait for the rescan to complete before returning |
| `--timeout` | `60s` | Timeout when waiting for rescan completion |

```bash
# Rescan a specific report
kubectl tlsreport rescan my-service-443-abc12345

# Rescan and wait for completion
kubectl tlsreport rescan my-service-443-abc12345 --wait

# Rescan all reports
kubectl tlsreport rescan --all

# Rescan all non-compliant reports
kubectl tlsreport rescan --all --status NonCompliant

# Rescan reports matching a label selector
kubectl tlsreport rescan --all -l host-network=true

# Rescan all reports in a namespace and wait
kubectl tlsreport rescan --all -n production --wait --timeout 120s
```

### target

Manage `TLSComplianceTarget` resources for scanning arbitrary host:port
endpoints (external services, partner APIs, etc.).

#### target list

```bash
kubectl tlsreport target list
```

Lists all targets with their host, port, status, associated report name,
last scan time, and age.

#### target create

```bash
kubectl tlsreport target create <host> <port>
```

Creates a `TLSComplianceTarget` resource. The operator picks it up and
creates a corresponding `TLSComplianceReport` within seconds.

```bash
# Scan an external endpoint
kubectl tlsreport target create google.com 443

# Scan an internal service by DNS
kubectl tlsreport target create my-api.partner.example.com 8443
```

#### target delete

```bash
kubectl tlsreport target delete <name> [--all]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Delete all TLSComplianceTargets |

```bash
# Delete a specific target
kubectl tlsreport target delete google-com-443

# Delete all targets
kubectl tlsreport target delete --all
```

### version

Print the plugin version.

```bash
kubectl tlsreport version
```

### completion

Generate shell completion scripts.

```bash
kubectl tlsreport completion [bash|zsh|fish|powershell]
```

```bash
# Bash
source <(kubectl-tlsreport completion bash)

# Zsh
source <(kubectl-tlsreport completion zsh)

# Fish
kubectl-tlsreport completion fish | source

# PowerShell
kubectl-tlsreport completion powershell | Out-String | Invoke-Expression
```

To load completions permanently, add the `source` line to your shell profile
(e.g. `~/.bashrc`, `~/.zshrc`).

## CI Gating with --fail-on-non-compliant

The `--fail-on-non-compliant` flag causes the plugin to exit with code 1
if any reports in the result set have a non-compliant status (NonCompliant,
NoTLS, or PlaintextHTTP). Infrastructure statuses like Timeout and
Unreachable do not trigger a failure.

The flag works with all subcommands and respects all filter flags, so you
can scope checks to specific namespaces, sources, or statuses:

```bash
# Gate on all endpoints
kubectl tlsreport summary --fail-on-non-compliant

# Gate on a specific namespace
kubectl tlsreport get -n production --fail-on-non-compliant

# Export JUnit and gate
kubectl tlsreport junit --fail-on-non-compliant > results.xml

# Gate on endpoints with expiring certificates
kubectl tlsreport get --expires-within 30d --fail-on-non-compliant
```

See [CI/CD Integration](ci-integration.md) for full pipeline examples
(GitHub Actions, Jenkins, Prow, Tekton).

---

Next: [Exporting Reports](exporting-reports.md)
