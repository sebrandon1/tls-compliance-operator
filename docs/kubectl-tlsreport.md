# kubectl-tlsreport Reference

The `kubectl-tlsreport` plugin provides CLI access to TLS compliance data
in your cluster. Once installed, kubectl discovers it as `kubectl tlsreport`.

## Install

### Krew (recommended)

```bash
kubectl krew install --manifest-url \
  https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/tlsreport.yaml
```

Once the plugin is in the [Krew index](https://krew.sigs.k8s.io/), this becomes
`kubectl krew install tlsreport`.

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

## Global Flags

These flags are available on all subcommands:

| Flag | Short | Description |
|------|-------|-------------|
| `--namespace` | `-n` | Filter by source namespace |
| `--status` | | Filter by compliance status (Compliant, NonCompliant, Warning, Unreachable, Timeout, Closed, Filtered, NoTLS, PlaintextHTTP, MutualTLSRequired, Pending, Unknown) |
| `--source` | | Filter by source kind (Service, Ingress, Route, Pod, HTTPRoute, TLSRoute, GRPCRoute, Gateway, Target) |
| `--pqc-status` | | Filter by PQC readiness (PQCReady, TLS13Capable, LegacyTLS, NoPQC) |
| `--expires-within` | | Show certs expiring within duration (e.g. 30d, 7d, 90d) |
| `--expired` | | Show only expired certificates |
| `--cert-issuer` | | Filter by certificate issuer (substring match) |
| `--cert-subject` | | Filter by certificate subject (substring match) |
| `--tls-version` | | Filter by TLS version support (`1.0`, `1.1`, `1.2`, `1.3`, `ssl3.0`; aliases `tls1.x`, `ssl30`, `3.0`). Invalid values error instead of matching nothing. |
| `--grade` | | Filter by exact cipher grade (A, B, C, D, F) |
| `--min-grade` | | Filter by minimum cipher grade (e.g. B shows A and B) |
| `--sort-by` | | Sort results (host, port, compliance, expiry, grade, pqc) |
| `--selector` | `-l` | Label selector to filter reports |
| `--fail-on-non-compliant` | | Exit with code 1 if any non-compliant endpoints are found |
| `--kubeconfig` | | Path to kubeconfig file |
| `--context` | | Kubeconfig context to use |

When a filter matches nothing, `get`, `summary`, export, `rescan --all`, and
`target list` print a single stderr message (`No reports match the specified
filters.` or `No targets match the specified filters.`) and skip table headers.
JSON/YAML still emit an empty array so pipelines keep working.

## Subcommands

### Export (root command)

Export reports in CSV, JSON, YAML, JUnit XML, Markdown, HTML, or SARIF format.
JSON and YAML default to a flattened snapshot schema; pass `--raw` to write
full `TLSComplianceReport` objects (ciphers, curves, profile compliance,
timestamps, errors, and certificate SANs).

```bash
kubectl tlsreport [csv|json|yaml|junit|markdown|md|html|sarif]
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

# Export as a self-contained HTML page
kubectl tlsreport html > tls-compliance.html

# Export SARIF for GitHub Code Scanning
kubectl tlsreport sarif > tls-compliance.sarif

# Export non-compliant endpoints as JSON
kubectl tlsreport json --status NonCompliant

# Export full TLSComplianceReport objects (status.tlsVersions, SANs, ciphers, errors)
kubectl tlsreport json --raw > reports.json
kubectl tlsreport yaml --raw > reports.yaml

# Export with CI gating (exit 1 on non-compliance)
kubectl tlsreport junit --fail-on-non-compliant > results.xml
```

### get

Display reports in a table. Supports `table`, `wide`, `json`, and `yaml`
output formats. Use `--watch` (`-w`) to stream create, update, and delete
events until you interrupt the command (Ctrl-C). Filters (`--status`, `-l`,
and the other report flags) apply to the initial snapshot and to later
events. Table output prints the header once, then one row per event;
JSON and YAML emit one object per event.

Default table columns: NAME, HOST, PORT, SOURCE, COMPLIANCE, GRADE, FS,
TLS 1.3, TLS 1.2, PQC, MLKEM.

```bash
kubectl tlsreport get [name] [-o format] [--watch]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `table` | Output format: table, wide, json, yaml |
| `--watch` | `-w` | `false` | Watch for create, update, and delete events |

```bash
# List all reports
kubectl tlsreport get

# Wide output (adds namespace, TLS 1.0, SSL 3.0, issuer, and cert expiry)
kubectl tlsreport get -o wide

# Get a specific report by name
kubectl tlsreport get my-service-443-abc12345

# Get non-compliant endpoints in a namespace
kubectl tlsreport get --status NonCompliant -n production

# Get reports as JSON
kubectl tlsreport get -o json

# Watch reports as they are created or updated
kubectl tlsreport get --watch

# Watch a single report
kubectl tlsreport get my-service-443-abc12345 --watch
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

Show an at-a-glance compliance summary with counts by status, source kind, PQC
readiness, cipher grade, TLS version support, namespace, hostname match, top
offenders (worst grades and soonest cert expiry), and certificate expiry
buckets.

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

### diff

Compare two JSON/YAML snapshots, or a snapshot against the live cluster.
Endpoints are matched by host:port.

```bash
kubectl tlsreport diff <before-file> [after-file] [--fail-on-regression] [-o text|json]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--fail-on-regression` | | `false` | Exit with code 1 if any endpoint got worse |
| `--output` | `-o` | `text` | Output format: text, json |

A regression is a worse compliance status, a lower cipher grade, newly enabled
legacy TLS (1.0/1.1/SSL 3.0), lost TLS 1.3, worse PQC readiness, or a newly
added non-compliant endpoint. Certificate expiry and issuer changes are
reported but are not regressions (rotation is expected).

```bash
# Capture a baseline, then compare against the live cluster
kubectl tlsreport json > before.json
kubectl tlsreport diff before.json

# Compare two files (before and after a cluster upgrade)
kubectl tlsreport json > after.json
kubectl tlsreport diff before.json after.json

# Fail CI when posture gets worse
kubectl tlsreport diff before.json after.json --fail-on-regression

# Machine-readable output
kubectl tlsreport diff before.json after.json -o json
```

With one file argument, filter flags (`-n`, `--status`, and so on) apply only
to the live cluster fetch. Filter flags cannot be combined with two file
arguments.

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

With `--all --wait`, progress is printed to stderr as a running count
(`scanned 42/120`) so a long wait does not look hung. The final
`Rescan completed for x/y reports` line is unchanged. `--wait=false`
prints only the trigger counts.

### target

Manage `TLSComplianceTarget` resources for scanning arbitrary host:port
endpoints (external services, partner APIs, etc.).

#### target list

```bash
kubectl tlsreport target list [-o table|wide|json|yaml] [--status status] [--sort-by field] [-l selector]
```

Lists targets with their host, port, status, associated report name,
last scan time, and age.

`--status`, `--sort-by`, and `-l` are the same global flags used by `get`.
`--sort-by` supports `host`, `port`, and `compliance` (alias: `status`).
Report-only keys (`expiry`, `grade`, `pqc`) are rejected.

```bash
kubectl tlsreport target list --status NonCompliant --sort-by host
kubectl tlsreport target list -l team=platform
```

#### target get

```bash
kubectl tlsreport target get <name> [-o table|wide|json|yaml]
```

```bash
kubectl tlsreport target get google-com-443
kubectl tlsreport target get google-com-443 -o json
```

#### target describe

```bash
kubectl tlsreport target describe <name>
```

```bash
kubectl tlsreport target describe google-com-443
```

#### target create

```bash
kubectl tlsreport target create <host> <port> [--wait] [--timeout duration]
```

Creates a `TLSComplianceTarget` resource. The operator picks it up and
creates a corresponding `TLSComplianceReport` within seconds.

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for the scan to complete and display the result |
| `--timeout` | `60s` | Timeout when waiting for scan completion |

```bash
# Scan an external endpoint
kubectl tlsreport target create google.com 443

# Scan an internal service by DNS
kubectl tlsreport target create my-api.partner.example.com 8443

# Create and wait for the scan result
kubectl tlsreport target create google.com 443 --wait --timeout 120s
```

#### target update

```bash
kubectl tlsreport target update <name> [--host host] [--port port]
```

Patches `spec.host` and/or `spec.port` on an existing target. At least one
of `--host` or `--port` is required. Changing host or port this way keeps
the target name and its linked report.

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | | New hostname or IP |
| `--port` | | New port (1–65535) |

```bash
# Update the host
kubectl tlsreport target update google-com-443 --host google.com

# Update the port
kubectl tlsreport target update google-com-443 --port 8443

# Update both
kubectl tlsreport target update google-com-443 --host google.com --port 443
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

The flag works with export, get, summary, and describe, and respects all
filter flags, so you can scope checks to specific namespaces, sources, or
statuses:

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
