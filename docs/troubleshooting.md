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
NetworkPolicy that only allows egress to common TLS ports (443, 6443, 8443,
9443). If your services use non-standard ports, either update the NetworkPolicy
or remove it:

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
| **Closed** | Port not listening | Check if service pods are running |
| **Timeout** | Connection timed out | Check network connectivity / firewall rules |
| **Filtered** | No response (firewall drop) | Check network policies |
| **NoTLS** | Port open but doesn't speak TLS | Expected for non-TLS services |
| **MutualTLSRequired** | Server requires client certificate | Expected for mTLS endpoints |
| **Pending** | Not yet checked | Wait for scan cycle |

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
