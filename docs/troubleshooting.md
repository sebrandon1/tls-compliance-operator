# Troubleshooting

## Reports Stuck in "Pending"

Reports start as `Pending` and transition after TLS checks complete. If reports
stay Pending for more than a few minutes:

**Check the operator logs:**

```bash
kubectl logs deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

**Check for NetworkPolicy restrictions.** The default install includes a
NetworkPolicy that allows egress to all ports. If your cluster policy requires
tighter restrictions, you can replace or remove the default NetworkPolicy:

```bash
kubectl delete networkpolicy tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

**Check rate limiting.** With the default rate of 10 checks/second, a cluster
with hundreds of endpoints will take several minutes to complete the initial
scan. You can increase throughput:

```yaml
env:
- name: TLS_COMPLIANCE_RATE_LIMIT
  value: "50"
- name: TLS_COMPLIANCE_WORKERS
  value: "20"
```

## "Closed" Status

`Closed` means the port is not listening (connection refused). This is normal
for services that don't have backing pods running:

```bash
$ kubectl describe tlsreport ocp4-cis-rs-openshift-compliance-8443-aab74008
...
Status:
  Compliance Status:  Closed
  Consecutive Errors: 4
  Last Error:         could not establish TLS connection to ocp4-cis-rs.openshift-compliance:8443 on any TLS version
Events:
  Warning  RetryExhausted  2m  tls-compliance-controller  TLS check retries exhausted for ocp4-cis-rs.openshift-compliance:8443 after 4 attempts: Closed
```

The operator retries (default 3 retries with 30s backoff) before marking as
Closed.

## Pod Not Starting on OpenShift

If the operator pod fails to schedule with SCC errors:

```
unable to validate against any security context constraint
```

Grant the appropriate SCC:

```bash
oc adm policy add-scc-to-user privileged \
  -z tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system

oc rollout restart deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

## Common Compliance Statuses

| Status | Meaning | Action |
|--------|---------|--------|
| **Compliant** | Supports TLS 1.2 or 1.3 | None needed |
| **NonCompliant** | Only supports TLS 1.0/1.1 | Upgrade TLS config |
| **Warning** | Supports modern TLS but also legacy versions | Remove legacy TLS support |
| **Closed** | Port not listening | Check if service pods are running |
| **Timeout** | Connection timed out | Check network connectivity / firewall rules |
| **Filtered** | Reserved (firewall drop); not currently produced | Check network policies |
| **Unreachable** | Could not connect (generic failure) | Check DNS resolution, verify the endpoint exists |
| **NoTLS** | Port open but doesn't speak TLS | Expected for non-TLS services |
| **PlaintextHTTP** | Endpoint responds with HTTP but no TLS | Add TLS termination via ingress controller or sidecar proxy |
| **MutualTLSRequired** | Server requires client certificate | Expected for mTLS endpoints; use `--client-cert`/`--client-key` to probe |
| **Pending** | Not yet checked | Wait for scan cycle |
| **Unknown** | Status could not be determined | Investigate endpoint health, check operator logs |

## Endpoints Stuck as Timeout or Unreachable

After 3 consecutive Timeout or Unreachable results, the operator opens a
circuit breaker for that report and skips further TLS checks for 15 minutes.
This avoids hammering dead endpoints. Successful checks close the circuit.
Skipped checks increment `tls_compliance_circuit_open_skipped_total`.

## Reports Accumulating / Not Being Cleaned Up

If old reports are piling up, report retention may be disabled (the default).
Enable it with `--report-retention-days`:

```yaml
env:
- name: TLS_COMPLIANCE_REPORT_RETENTION_DAYS
  value: "90"
```

Reports with no scan activity for the configured number of days are removed
during each cleanup cycle. Monitor deletions with:

```promql
increase(tls_compliance_reports_ttl_deleted_total[24h])
```

See [Report Retention](configuration.md#report-retention) for details.

## Viewing Operator Configuration

The operator logs its configuration at startup:

```
INFO  setup  TLS checker configured  {"timeout": "5s", "rateLimit": 10, "rateBurst": 20,
  "scanInterval": "1h0m0s", "cleanupInterval": "5m0s", "certExpiryWarningDays": 30,
  "includeNamespaces": [], "excludeNamespaces": [], "workers": 5, "maxRetries": 3,
  "retryBackoff": "30s"}
```

---

Back to [README](../README.md)
